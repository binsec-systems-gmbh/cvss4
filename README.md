# CVSS 4.0 calculator in python

This library provides a CVSS 4.0 score calculator based on a given vector
string.

The calculator is based on specifications and the reference implementation which can be found here:
- https://www.first.org/cvss/v4.0/specification-document
- https://github.com/FIRSTdotorg/cvss-v4-calculator/

## License

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

- http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

## Usage

```python

from cvss4 import CVSS4Calculator

CVSS4Calculator.calc('CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/E:A/MSI:S')
Decimal('7.8')
```
