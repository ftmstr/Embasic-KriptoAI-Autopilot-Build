"""Invented data only; no network or real market evaluation."""
import io
import json
import unittest
import zipfile
from safe_public_ci.boundaries import UnsafeInput, validate_synthetic_json, validate_zip_envelope, validate_parquet_envelope

def toy_zip(name="toy.txt", data=b"toy"):
    b = io.BytesIO()
    with zipfile.ZipFile(b,"w",zipfile.ZIP_DEFLATED) as z:
        z.writestr(name,data)
    return b.getvalue()

class BoundaryTests(unittest.TestCase):
    def test_json_valid(self):
        obj={"kind":"synthetic-v1","records":[{"index":0,"value":3}]}
        self.assertEqual(len(validate_synthetic_json(json.dumps(obj).encode())),1)
    def test_json_nonsynthetic(self):
        with self.assertRaises(UnsafeInput): validate_synthetic_json(b'{"kind":"live","records":[]}')
    def test_json_duplicate(self):
        with self.assertRaises(UnsafeInput): validate_synthetic_json(b'{"kind":"synthetic-v1","kind":"synthetic-v1","records":[]}')
    def test_json_nan(self):
        with self.assertRaises(UnsafeInput): validate_synthetic_json(b'{"kind":"synthetic-v1","records":[{"index":0,"value":NaN}]}')
    def test_json_index(self):
        with self.assertRaises(UnsafeInput): validate_synthetic_json(b'{"kind":"synthetic-v1","records":[{"index":1,"value":2},{"index":1,"value":3}]}')
    def test_json_oversized(self):
        with self.assertRaises(UnsafeInput): validate_synthetic_json(b"x"*65537)
    def test_zip_valid(self):
        self.assertEqual(validate_zip_envelope(toy_zip())["entries"],1)
    def test_zip_traversal(self):
        with self.assertRaises(UnsafeInput): validate_zip_envelope(toy_zip("../evil"))
    def test_zip_absolute(self):
        with self.assertRaises(UnsafeInput): validate_zip_envelope(toy_zip("/evil"))
    def test_zip_bomb(self):
        with self.assertRaises(UnsafeInput): validate_zip_envelope(toy_zip("bomb",b"0"*50000))
    def test_zip_corruption(self):
        with self.assertRaises(UnsafeInput): validate_zip_envelope(b"broken")
    def test_parquet_envelope(self):
        self.assertEqual(validate_parquet_envelope(b"PAR1"+b"abcd"+(4).to_bytes(4,"little")+b"PAR1"),4)
    def test_parquet_bad(self):
        with self.assertRaises(UnsafeInput): validate_parquet_envelope(b"PAR1PAR1")
