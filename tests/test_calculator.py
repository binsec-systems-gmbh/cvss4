# Copyright binsec group GmbH
# (https://binsec-group.com/)

# ruff: noqa

import unittest

from decimal import Decimal

from cvss4 import CVSS4Calculator, CVSS4Vector


class CalculatorTest(unittest.TestCase):
  def test_none(self):
    vectors = [
        'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N',
        'CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N',
        'CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N',
        'CVSS:4.0/AV:P/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N',

        'CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N',

        'CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N',

        'CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N',
        'CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N',

        'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N',
        'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N',
    ]
    for v in vectors:
      self.assertEqual(CVSS4Calculator.calc(CVSS4Vector(v)), Decimal('0.0'))

  def test_10(self):
    vectors = [
        'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H',
    ]
    for v in vectors:
      self.assertEqual(CVSS4Calculator.calc(CVSS4Vector(v)), Decimal('10.0'))

  def test_basic(self):
    vectors = {
        'CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:N/VI:H/VA:H/SC:L/SI:H/SA:H': '8.4',
        'CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:N/VI:H/VA:H/SC:L/SI:L/SA:H': '8.4',
        'CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:N/VI:H/VA:H/SC:H/SI:H/SA:H': '8.5',
        'CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:N/VI:H/VA:H/SC:L/SI:N/SA:H': '8.3',
    }
    for v, s in vectors.items():
      self.assertEqual(CVSS4Calculator.calc(CVSS4Vector(v)), Decimal(s))

  def test_extended(self):
    vectors = {
        'CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/E:P': '2.0',
        'CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/E:A': '5.1',
        'CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/E:A/MSI:S': '7.8',
        'CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/E:A/MSI:S/MSA:S': '8.0',
        'CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/E:A/MSI:H/MSA:H': '6.3',
    }
    for v, s in vectors.items():
      self.assertEqual(CVSS4Calculator.calc(CVSS4Vector(v)), Decimal(s))
