"""Local multilingual semantic intent-shift scoring with persistent caching."""

from __future__ import annotations

import hashlib
import math
import re
import sqlite3
from dataclasses import asdict, dataclass
from pathlib import Path


DEFAULT_MODEL = "intfloat/multilingual-e5-small"
DEFAULT_REVISION = "fd1525a9fd15316a2d503bf26ab031a61d056e98"


@dataclass(frozen=True)
class EmbeddingConfig:
    model_id: str = DEFAULT_MODEL
    revision: str = DEFAULT_REVISION
    onnx_filename: str = "onnx/model.onnx"
    max_length: int = 512
    max_chunk_chars: int = 1400
    cache_path: str | None = None


class EmbeddingDependencyError(RuntimeError):
    pass


def _vector_key(model_key: str, role: str, text: str) -> str:
    payload = f"{model_key}\0{role}\0{text}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _normalize(vector):
    import numpy as np

    vector = np.asarray(vector, dtype=np.float32)
    norm = float(np.linalg.norm(vector))
    return vector / norm if norm else vector


def _cosine(left, right) -> float:
    import numpy as np

    return float(np.clip(np.dot(left, right), -1.0, 1.0))


def chunk_external_text(text: str, max_chars: int = 1400) -> list[str]:
    """Keep injected lines visible while bounding encoder sequence lengths."""
    units = [part.strip() for part in re.split(r"(?:\r?\n){1,}|(?<=[.!?])\s+", text) if part.strip()]
    if not units:
        return [text]
    chunks: list[str] = []
    pending = ""
    for unit in units:
        if len(unit) > max_chars:
            if pending:
                chunks.append(pending)
                pending = ""
            chunks.extend(unit[index : index + max_chars] for index in range(0, len(unit), max_chars))
        elif pending and len(pending) + 1 + len(unit) > max_chars:
            chunks.append(pending)
            pending = unit
        else:
            pending = f"{pending}\n{unit}".strip()
    if pending:
        chunks.append(pending)
    return chunks


class EmbeddingIntentScorer:
    """Compute max query-to-context-chunk cosine distance using multilingual E5.

    E5's documented ``query:``/``passage:`` prefixes are retained.  The score
    is ``1 - min(cosine_similarity)`` across context chunks, clipped to [0, 1].
    Max distance is intentional: a short off-task injection must not disappear
    inside a long retrieved document.
    """

    method = "multilingual_e5_max_chunk_cosine_distance"

    def __init__(self, config: EmbeddingConfig | None = None):
        self.config = config or EmbeddingConfig()
        try:
            import numpy as np
            import onnxruntime as ort
            from huggingface_hub import hf_hub_download
            from transformers import AutoTokenizer
        except ImportError as exc:
            raise EmbeddingDependencyError(
                "Install requirements-embedding.txt before using semantic Dintent"
            ) from exc

        self._np = np
        model_path = hf_hub_download(
            repo_id=self.config.model_id,
            filename=self.config.onnx_filename,
            revision=self.config.revision,
        )
        self.tokenizer = AutoTokenizer.from_pretrained(
            self.config.model_id, revision=self.config.revision
        )
        self.session = ort.InferenceSession(model_path, providers=["CPUExecutionProvider"])
        self.input_names = {item.name for item in self.session.get_inputs()}
        self.model_key = (
            f"{self.config.model_id}@{self.config.revision}:"
            f"{self.config.onnx_filename}:max{self.config.max_length}"
        )
        self._memory: dict[str, object] = {}
        self._db: sqlite3.Connection | None = None
        if self.config.cache_path:
            cache_path = Path(self.config.cache_path)
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            self._db = sqlite3.connect(cache_path)
            self._db.execute(
                "CREATE TABLE IF NOT EXISTS embeddings "
                "(cache_key TEXT PRIMARY KEY, dims INTEGER NOT NULL, vector BLOB NOT NULL)"
            )
            self._db.commit()

    def metadata(self) -> dict:
        return {**asdict(self.config), "method": self.method, "model_key": self.model_key}

    def close(self) -> None:
        if self._db is not None:
            self._db.commit()
            self._db.close()
            self._db = None

    def _load_cached(self, key: str):
        if key in self._memory:
            return self._memory[key]
        if self._db is None:
            return None
        row = self._db.execute(
            "SELECT dims, vector FROM embeddings WHERE cache_key = ?", (key,)
        ).fetchone()
        if row is None:
            return None
        vector = self._np.frombuffer(row[1], dtype=self._np.float32, count=row[0]).copy()
        self._memory[key] = vector
        return vector

    def _save_cached(self, key: str, vector) -> None:
        self._memory[key] = vector
        if self._db is not None:
            self._db.execute(
                "INSERT OR REPLACE INTO embeddings(cache_key, dims, vector) VALUES (?, ?, ?)",
                (key, int(vector.shape[0]), vector.astype(self._np.float32).tobytes()),
            )
            self._db.commit()

    def embed(self, text: str, role: str) -> object:
        if role not in {"query", "passage"}:
            raise ValueError("role must be query or passage")
        key = _vector_key(self.model_key, role, text)
        cached = self._load_cached(key)
        if cached is not None:
            return cached
        encoded = self.tokenizer(
            f"{role}: {text}",
            max_length=self.config.max_length,
            truncation=True,
            padding=True,
            return_tensors="np",
        )
        feed = {
            name: encoded[name].astype(self._np.int64)
            for name in self.input_names
            if name in encoded
        }
        if "token_type_ids" in self.input_names and "token_type_ids" not in feed:
            feed["token_type_ids"] = self._np.zeros_like(feed["input_ids"], dtype=self._np.int64)
        output = self.session.run(None, feed)[0]
        mask = encoded["attention_mask"].astype(bool)[..., None]
        pooled = (output * mask).sum(axis=1) / self._np.maximum(mask.sum(axis=1), 1)
        vector = _normalize(pooled[0])
        self._save_cached(key, vector)
        return vector

    def score(self, xuser: str, xext: str) -> float:
        query = self.embed(xuser, "query")
        chunks = chunk_external_text(xext, self.config.max_chunk_chars)
        similarities = [_cosine(query, self.embed(chunk, "passage")) for chunk in chunks]
        if not similarities or not all(math.isfinite(value) for value in similarities):
            return 0.0
        return round(min(max(1.0 - min(similarities), 0.0), 1.0), 6)
