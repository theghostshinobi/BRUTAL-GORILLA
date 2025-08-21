# securebert_adapter.py
# Minimal, offline-first loader/adapter for a local SecureBERT snapshot.
# - Single init (singleton) for tokenizer + backbone
# - embed(text): CLS or mean-pooled embeddings (numpy)
# - classify(text): optional (only if a fine-tuned classification head exists)
# - NO internet calls (local_files_only=True). If folder missing → clear hint.
#
# Added for compat with orch_report:
#   - load(path, ...) helper
#   - SecureBERT(path, ...) class alias
#
# Usage:
#   from securebert_adapter import get_adapter, load, SecureBERT
#   sb = load("models/SecureBERT")        # or get_adapter(path=...)
#   vecs = sb.embed(["hello world"])
#   preds = sb.classify(["suspicious"])    # only if clf head available

from __future__ import annotations

import os
import time
import logging
from typing import Any, Dict, List, Optional, Tuple, Union

logger = logging.getLogger(__name__)
if not logger.handlers:
    logging.basicConfig(level=logging.INFO)

__all__ = [
    "SecureBERTAdapter", "get_adapter", "embed", "classify",
    "load", "SecureBERT"
]

# -------------------------- env/config defaults --------------------------- #

# Directory containing the *base* SecureBERT snapshot (tokenizer + backbone)
_DEFAULT_SB_PATH = os.getenv("SECUREBERT_PATH", "models/SecureBERT")
# Optional directory containing a fine-tuned classification head
_DEFAULT_CLF_PATH = os.getenv("SECUREBERT_CLF_PATH", "models/SecureBERT_clf")

# Singleton backing store
_ADAPTER_SINGLETON: "SecureBERTAdapter | None" = None


# ------------------------------- helpers --------------------------------- #

def _exists_model_dir(path: str) -> bool:
    """Heuristic check for a local HF model dir (no internet)."""
    if not path or not os.path.isdir(path):
        return False
    expected_any = (
        "config.json",
        "tokenizer.json",
        "vocab.txt",
        "merges.txt",
        "tokenizer.model",
        "pytorch_model.bin",
        "model.safetensors",
    )
    try:
        files = set(os.listdir(path))
    except Exception:
        return False
    return any(name in files for name in expected_any)


def _offline_hint(path: str) -> str:
    return (
        "[SecureBERT] Modello non trovato in '{0}'.\n"
        "Scarica una snapshot in locale e imposta SECUREBERT_PATH o config.securebert_path.\n"
        "Esempi (una tantum, con internet):\n"
        "  huggingface-cli download seyonec/SecureBERT --local-dir {0}\n"
        "Oppure copia manualmente i file di modello dentro: {0}\n"
        "Nota: l'adapter è offline-first e usa local_files_only=True."
    ).format(path)


# --------------------------- core adapter class --------------------------- #

class SecureBERTAdapter:
    """
    Lazy, offline adapter around a local SecureBERT snapshot.

    Params
    ------
    base_dir: str
        Path to the base SecureBERT (tokenizer + backbone).
    clf_dir: Optional[str]
        Path to an optional fine-tuned classification head (same tokenizer).
    device: str
        "cpu" (default) or a torch device string if available.
    pooling: str
        "mean" (default) or "cls" to choose embedding pooling strategy.
    max_length: int
        Max token length for encoding.
    """

    def __init__(self,
                 base_dir: str,
                 clf_dir: Optional[str] = None,
                 device: str = "cpu",
                 pooling: str = "mean",
                 max_length: int = 256) -> None:
        self.base_dir = base_dir
        self.clf_dir = clf_dir if clf_dir and _exists_model_dir(clf_dir) else None
        self.device = device
        self.pooling = (pooling or "mean").lower().strip()
        if self.pooling not in ("mean", "cls"):
            self.pooling = "mean"
        self.max_length = int(max_length) if max_length else 256

        self._tok = None
        self._base = None
        self._clf = None
        self._labels = None  # Optional[List[str]]

        self._torch = None
        self._np = None

        self._loaded = False
        self._clf_loaded = False

    # -------------------------- lazy imports -------------------------- #

    def _ensure_libs(self) -> bool:
        if self._torch is not None and self._np is not None:
            return True
        try:
            import torch  # type: ignore
            import numpy as np  # type: ignore
            self._torch = torch
            self._np = np
            return True
        except Exception as e:
            logger.warning("Torch/Numpy non disponibili: %s (embed/classify disabilitati).", e)
            return False

    # -------------------------- model loading ------------------------- #

    def _load_backbone(self) -> None:
        if self._loaded:
            return
        if not _exists_model_dir(self.base_dir):
            logger.error(_offline_hint(self.base_dir))
            return
        if not self._ensure_libs():
            return

        t0 = time.time()
        try:
            from transformers import AutoTokenizer, AutoModel  # type: ignore
        except Exception as e:
            logger.warning("transformers non disponibile: %s", e)
            return

        try:
            self._tok = AutoTokenizer.from_pretrained(self.base_dir, local_files_only=True)
            self._base = AutoModel.from_pretrained(self.base_dir, local_files_only=True)
            self._base.eval()
            # move to device if possible
            if self.device and self.device != "cpu":
                try:
                    self._base.to(self.device)
                except Exception:
                    pass
            self._loaded = True
            logger.info("SecureBERT backbone loaded in %.2fs (dir=%s)", time.time() - t0, self.base_dir)
        except Exception as e:
            logger.error("Impossibile caricare SecureBERT da '%s' (offline): %s", self.base_dir, e)
            logger.error(_offline_hint(self.base_dir))

    def _load_classifier(self) -> None:
        if self._clf_loaded or not self.clf_dir:
            return
        if not _exists_model_dir(self.clf_dir):
            logger.warning("Testa di classificazione non trovata in '%s' (classify() disabilitato).", self.clf_dir)
            return
        if not self._ensure_libs():
            return

        try:
            from transformers import AutoModelForSequenceClassification  # type: ignore
        except Exception as e:
            logger.warning("transformers non disponibile per classificazione: %s", e)
            return

        t0 = time.time()
        try:
            self._clf = AutoModelForSequenceClassification.from_pretrained(self.clf_dir, local_files_only=True)
            self._clf.eval()
            # try to grab label mapping if present
            try:
                config = getattr(self._clf, "config", None)
                if config and getattr(config, "id2label", None):
                    id2label = config.id2label
                    max_id = max(int(i) for i in id2label.keys())
                    labels = [""] * (max_id + 1)
                    for i, name in id2label.items():
                        labels[int(i)] = str(name)
                    self._labels = labels
            except Exception:
                self._labels = None

            if self.device and self.device != "cpu":
                try:
                    self._clf.to(self.device)
                except Exception:
                    pass

            self._clf_loaded = True
            logger.info("SecureBERT classifier head loaded in %.2fs (dir=%s)", time.time() - t0, self.clf_dir)
        except Exception as e:
            logger.warning("Impossibile caricare testa di classificazione da '%s': %s", self.clf_dir, e)

    # ---------------------------- public API -------------------------- #

    def ready(self) -> bool:
        """True if backbone is loaded."""
        if not self._loaded:
            self._load_backbone()
        return bool(self._loaded)

    def classify_ready(self) -> bool:
        """True if classifier head is loaded."""
        if not self._clf_loaded:
            self._load_classifier()
        return bool(self._clf_loaded and self._clf is not None)

    @staticmethod
    def _as_list(texts: Union[str, List[str]]) -> List[str]:
        if isinstance(texts, str):
            return [texts]
        return [str(t) for t in (texts or [])]

    def _encode(self, texts: List[str]):
        if not self.ready():
            return None
        tok = self._tok
        assert tok is not None
        return tok(
            texts,
            padding=True,
            truncation=True,
            max_length=self.max_length,
            return_tensors="pt"
        )

    def embed(self, texts: Union[str, List[str]]) -> "np.ndarray | None":
        """
        Returns a numpy array (N, D) of embeddings using:
          - mean pooling (default) over token embeddings with attention mask, OR
          - CLS vector if pooling='cls'.
        Returns None if unavailable.
        """
        if not self.ready() or not self._ensure_libs():
            return None

        np = self._np
        torch = self._torch
        base = self._base
        assert np is not None and torch is not None and base is not None

        arr = self._as_list(texts)
        if not arr:
            return np.zeros((0, getattr(base.config, "hidden_size", 768)), dtype="float32")

        enc = self._encode(arr)
        if enc is None:
            return None

        input_ids = enc["input_ids"]
        attn_mask = enc.get("attention_mask", None)
        if self.device and self.device != "cpu":
            try:
                input_ids = input_ids.to(self.device)
                if attn_mask is not None:
                    attn_mask = attn_mask.to(self.device)
            except Exception:
                pass

        ctx = getattr(torch, "inference_mode", torch.no_grad)()
        with ctx:
            outputs = base(input_ids=input_ids, attention_mask=attn_mask)
            hidden = outputs.last_hidden_state  # (B, T, H)

            if self.pooling == "cls":
                emb = hidden[:, 0, :]  # (B, H)
            else:
                if attn_mask is None:
                    emb = hidden.mean(dim=1)
                else:
                    mask = attn_mask.unsqueeze(-1).type_as(hidden)  # (B, T, 1)
                    summed = (hidden * mask).sum(dim=1)
                    counts = mask.sum(dim=1).clamp(min=1e-9)
                    emb = summed / counts

        try:
            emb = emb.detach().cpu().numpy().astype("float32", copy=False)
        except Exception:
            emb = emb.detach().cpu().numpy()
        return emb

    def classify(self, texts: Union[str, List[str]]) -> List[Dict[str, Any]]:
        """
        Returns per-text classification scores if a fine-tuned head is available.
        Output: List[{"labels": [...], "scores": [...], "top": {"label": str, "score": float}}]
        If the head is missing/unavailable, returns [].
        """
        if not self.classify_ready() or not self._ensure_libs():
            return []

        np = self._np  # noqa: F841 (kept for symmetry; may be useful for downstream)
        torch = self._torch
        clf = self._clf
        assert torch is not None and clf is not None

        arr = self._as_list(texts)
        if not arr:
            return []

        enc = self._encode(arr)
        if enc is None:
            return []

        input_ids = enc["input_ids"]
        attn_mask = enc.get("attention_mask", None)
        if self.device and self.device != "cpu":
            try:
                input_ids = input_ids.to(self.device)
                if attn_mask is not None:
                    attn_mask = attn_mask.to(self.device)
            except Exception:
                pass

        ctx = getattr(torch, "inference_mode", torch.no_grad)()
        with ctx:
            logits = clf(input_ids=input_ids, attention_mask=attn_mask).logits  # (B, C)
            probs = torch.softmax(logits, dim=-1)  # (B, C)
            probs_np = probs.detach().cpu().numpy()

        labels = self._labels or [str(i) for i in range(probs_np.shape[1])]
        out: List[Dict[str, Any]] = []
        for row in probs_np:
            top_idx = int(row.argmax())
            out.append({
                "labels": labels,
                "scores": [float(x) for x in row.tolist()],
                "top": {"label": labels[top_idx], "score": float(row[top_idx])}
            })
        return out

    # ----------------------------- misc/info --------------------------- #

    def info(self) -> Dict[str, Any]:
        return {
            "base_dir": self.base_dir,
            "clf_dir": self.clf_dir,
            "loaded": self._loaded,
            "clf_loaded": self._clf_loaded,
            "device": self.device,
            "pooling": self.pooling,
            "max_length": self.max_length,
        }


# ------------------------------- factory ---------------------------------- #

def get_adapter(path: Optional[str] = None,
                clf_path: Optional[str] = None,
                device: str = "cpu",
                pooling: str = "mean",
                max_length: int = 256) -> SecureBERTAdapter:
    """
    Returns a process-wide singleton adapter (lazy-loaded).
    Reuses the existing instance if already created.
    """
    global _ADAPTER_SINGLETON
    base_dir = path or _DEFAULT_SB_PATH
    head_dir = clf_path or (_DEFAULT_CLF_PATH if _exists_model_dir(_DEFAULT_CLF_PATH) else None)

    if _ADAPTER_SINGLETON is not None:
        return _ADAPTER_SINGLETON

    adapter = SecureBERTAdapter(
        base_dir=base_dir,
        clf_dir=head_dir,
        device=device,
        pooling=pooling,
        max_length=max_length,
    )
    _ADAPTER_SINGLETON = adapter
    return adapter


# --------------------------- convenience API ------------------------------- #

def embed(texts: Union[str, List[str]],
          path: Optional[str] = None,
          device: str = "cpu",
          pooling: str = "mean",
          max_length: int = 256):
    """Convenience: get (N, D) embeddings or None if unavailable."""
    sb = get_adapter(path=path, device=device, pooling=pooling, max_length=max_length)
    return sb.embed(texts)

def classify(texts: Union[str, List[str]],
             path: Optional[str] = None,
             clf_path: Optional[str] = None,
             device: str = "cpu",
             pooling: str = "mean",
             max_length: int = 256) -> List[Dict[str, Any]]:
    """Convenience: classification if a head exists; [] otherwise."""
    sb = get_adapter(path=path, clf_path=clf_path, device=device, pooling=pooling, max_length=max_length)
    return sb.classify(texts)


# --------------------------- orch_report compat ---------------------------- #

def load(path: Optional[str] = None,
         clf_path: Optional[str] = None,
         device: str = "cpu",
         pooling: str = "mean",
         max_length: int = 256) -> SecureBERTAdapter:
    """
    Compatibility helper expected by orch_report._maybe_load_securebert().
    """
    return get_adapter(path=path, clf_path=clf_path, device=device, pooling=pooling, max_length=max_length)

class SecureBERT(SecureBERTAdapter):
    """
    Compatibility class expected by orch_report._maybe_load_securebert().
    Note: this does NOT use the singleton to preserve the legacy constructor
    semantics. Prefer get_adapter/load for singleton behavior.
    """
    def __init__(self, path: str,
                 clf_path: Optional[str] = None,
                 device: str = "cpu",
                 pooling: str = "mean",
                 max_length: int = 256) -> None:
        super().__init__(base_dir=path, clf_dir=clf_path, device=device, pooling=pooling, max_length=max_length)


# ------------------------------- module main ------------------------------- #

if __name__ == "__main__":
    # Dry run: print adapter info and small smoke test without raising.
    sb = get_adapter()
    print("[securebert_adapter] info:", sb.info())
    if sb.ready():
        out = sb.embed(["test"])
        shape = None if out is None else tuple(out.shape)
        print("[securebert_adapter] embed('test') shape:", shape)
    else:
        print(_offline_hint(sb.base_dir))
    if sb.classify_ready():
        pred = sb.classify(["test"])
        print("[securebert_adapter] classify('test'):", pred[:1])
    else:
        print("[securebert_adapter] classify: head not available (optional).")
