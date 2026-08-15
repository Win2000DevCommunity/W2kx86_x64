"""Integration with the external UBRT shift engine.

Extracted from the legacy ``x86_x64.py`` by ``tools/split_translator.py``.
"""

from __future__ import annotations

from .runtime import *  # noqa: F401,F403


class UbrtMixin:
    """See the module docstring."""

    def _load_ubrt_refs(self):
        """Lazy-load UBRT reference database from win2k_analyzer."""
        if self._ubrt_ref_db is not None:
            return self._ubrt_ref_db
        self._ubrt_ref_db = []
        if not HAS_UBRT or not self.source_path or not os.path.isfile(self.source_path):
            return self._ubrt_ref_db
        try:
            finder = PEReferenceFinder(self.source_path)
            db = finder.find_all()
            self._ubrt_ref_db = list(db._refs)  # noqa: SLF001 — internal list
        except Exception as exc:
            self.warnings.append(f"  [UBRT] reference scan failed: {exc}")
            self._ubrt_ref_db = []
        return self._ubrt_ref_db

    @staticmethod
    def ubrt_insert_bytes(pe_path: str, rva: int, data: bytes,
                          out_path: Optional[str] = None) -> Tuple[bytes, dict]:
        """
        Size-changing insert on a finished PE using win2k_analyzer UBRT.

        Shifts trailing bytes and recalculates relative branches, relocations,
        exports, and resource directory RVAs — prefer over NOP sleds when a
        patch needs more space than the original instruction span.
        """
        if not HAS_UBRT or UBRTEngine is None:
            raise RuntimeError("UBRT engine unavailable (win2k_analyzer not on path)")
        eng = UBRTEngine()
        info = eng.load(pe_path)
        if not info.get('success', True) or not eng.shift_engine:
            raise RuntimeError(f"UBRT failed to load {pe_path}: {info}")
        result = eng.insert(rva, data)
        blob = eng.save(out_path or pe_path)
        summary = {
            'delta': result.delta,
            'refs_updated': result.refs_updated,
            'warnings': list(result.warnings),
        }
        return blob, summary

    @staticmethod
    def ubrt_delete_bytes(pe_path: str, rva: int, count: int,
                          out_path: Optional[str] = None) -> Tuple[bytes, dict]:
        """Delete bytes at RVA; trailing code and refs shift down."""
        if not HAS_UBRT or UBRTEngine is None:
            raise RuntimeError("UBRT engine unavailable (win2k_analyzer not on path)")
        eng = UBRTEngine()
        info = eng.load(pe_path)
        if not info.get('success', True) or not eng.shift_engine:
            raise RuntimeError(f"UBRT failed to load {pe_path}: {info}")
        result = eng.delete(rva, count)
        blob = eng.save(out_path or pe_path)
        return blob, {
            'delta': result.delta,
            'refs_updated': result.refs_updated,
            'warnings': list(result.warnings),
        }

    @staticmethod
    def ubrt_patch_bytes(pe_path: str, rva: int, data: bytes,
                         out_path: Optional[str] = None) -> Tuple[bytes, dict]:
        """Same-size in-place patch (branches unchanged when size matches)."""
        if not HAS_UBRT or UBRTEngine is None:
            raise RuntimeError("UBRT engine unavailable (win2k_analyzer not on path)")
        eng = UBRTEngine()
        info = eng.load(pe_path)
        if not info.get('success', True) or not eng.shift_engine:
            raise RuntimeError(f"UBRT failed to load {pe_path}: {info}")
        result = eng.patch(rva, data)
        blob = eng.save(out_path or pe_path)
        return blob, {
            'delta': result.delta,
            'refs_updated': result.refs_updated,
            'warnings': list(result.warnings),
        }

    @staticmethod
    def ubrt_mutate(pe_path: str, ops: List[Tuple[str, ...]],
                    out_path: Optional[str] = None) -> Tuple[bytes, dict]:
        """
        Apply a sequence of UBRT shift operations on a finished PE.

        Each op is (kind, rva, payload) where kind is ``insert`` | ``delete`` |
        ``patch`` and payload is bytes (insert/patch) or int count (delete).
        Recalculates branches, relocs, exports, and resource RVAs after each op.
        """
        if not HAS_UBRT or UBRTEngine is None:
            raise RuntimeError("UBRT engine unavailable (win2k_analyzer not on path)")
        eng = UBRTEngine()
        info = eng.load(pe_path)
        if not info.get('success', True) or not eng.shift_engine:
            raise RuntimeError(f"UBRT failed to load {pe_path}: {info}")
        applied = 0
        warnings: List[str] = []
        refs = 0
        for op in ops:
            kind = op[0].lower()
            rva = int(op[1])
            if kind == 'insert':
                result = eng.insert(rva, op[2])
            elif kind == 'delete':
                result = eng.delete(rva, int(op[2]))
            elif kind == 'patch':
                result = eng.patch(rva, op[2])
            else:
                raise ValueError(f"unknown UBRT op: {kind}")
            if result.success:
                applied += 1
                refs += result.refs_updated
                warnings.extend(result.warnings)
        blob = eng.save(out_path or pe_path)
        return blob, {'ops': applied, 'refs_updated': refs, 'warnings': warnings}

