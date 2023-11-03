# Copyright binsec group GmbH
# (https://binsec-group.com/)

# ruff: noqa

import unittest

from cvss4.vector import CVSS4Vector

class VectorTest(unittest.TestCase):
  def test_valid(self):
    v = CVSS4Vector('CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N')
    self.assertDictEqual(v._data, {
        'AV': 'N', 'AC': 'L', 'AT': 'N', 'PR': 'L', 'UI': 'N',
        'VC': 'N', 'VI': 'N', 'VA': 'N', 'SC': 'N', 'SI': 'N', 'SA': 'N',
        'AR': None, 'CR': None, 'IR': None, 'E': None, 'MSI': None, 'MSA': None,
    })

  def test_defaults(self):
    v = CVSS4Vector('CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N')
    self.assertDictEqual(v.asdict(), {
        'AV': 'N', 'AC': 'L', 'AT': 'N', 'PR': 'L', 'UI': 'N',
        'VC': 'N', 'VI': 'N', 'VA': 'N', 'SC': 'N', 'SI': 'N', 'SA': 'N',
        'AR': 'H', 'CR': 'H', 'IR': 'H', 'E': 'A', 'MSI': None, 'MSA': None,
    })
