# Copyright 2023 binsec systems GmbH
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from decimal import Decimal

SCORE_MAP = {
    '000000': Decimal('10'),
    '000001': Decimal('9.9'),
    '000010': Decimal('9.8'),
    '000011': Decimal('9.5'),
    '000020': Decimal('9.5'),
    '000021': Decimal('9.2'),
    '000100': Decimal('10'),
    '000101': Decimal('9.6'),
    '000110': Decimal('9.3'),
    '000111': Decimal('8.7'),
    '000120': Decimal('9.1'),
    '000121': Decimal('8.1'),
    '000200': Decimal('9.3'),
    '000201': Decimal('9'),
    '000210': Decimal('8.9'),
    '000211': Decimal('8'),
    '000220': Decimal('8.1'),
    '000221': Decimal('6.8'),
    '001000': Decimal('9.8'),
    '001001': Decimal('9.5'),
    '001010': Decimal('9.5'),
    '001011': Decimal('9.2'),
    '001020': Decimal('9'),
    '001021': Decimal('8.4'),
    '001100': Decimal('9.3'),
    '001101': Decimal('9.2'),
    '001110': Decimal('8.9'),
    '001111': Decimal('8.1'),
    '001120': Decimal('8.1'),
    '001121': Decimal('6.5'),
    '001200': Decimal('8.8'),
    '001201': Decimal('8'),
    '001210': Decimal('7.8'),
    '001211': Decimal('7'),
    '001220': Decimal('6.9'),
    '001221': Decimal('4.8'),
    '002001': Decimal('9.2'),
    '002011': Decimal('8.2'),
    '002021': Decimal('7.2'),
    '002101': Decimal('7.9'),
    '002111': Decimal('6.9'),
    '002121': Decimal('5'),
    '002201': Decimal('6.9'),
    '002211': Decimal('5.5'),
    '002221': Decimal('2.7'),
    '010000': Decimal('9.9'),
    '010001': Decimal('9.7'),
    '010010': Decimal('9.5'),
    '010011': Decimal('9.2'),
    '010020': Decimal('9.2'),
    '010021': Decimal('8.5'),
    '010100': Decimal('9.5'),
    '010101': Decimal('9.1'),
    '010110': Decimal('9'),
    '010111': Decimal('8.3'),
    '010120': Decimal('8.4'),
    '010121': Decimal('7.1'),
    '010200': Decimal('9.2'),
    '010201': Decimal('8.1'),
    '010210': Decimal('8.2'),
    '010211': Decimal('7.1'),
    '010220': Decimal('7.2'),
    '010221': Decimal('5.3'),
    '011000': Decimal('9.5'),
    '011001': Decimal('9.3'),
    '011010': Decimal('9.2'),
    '011011': Decimal('8.5'),
    '011020': Decimal('8.5'),
    '011021': Decimal('7.3'),
    '011100': Decimal('9.2'),
    '011101': Decimal('8.2'),
    '011110': Decimal('8'),
    '011111': Decimal('7.2'),
    '011120': Decimal('7'),
    '011121': Decimal('5.9'),
    '011200': Decimal('8.4'),
    '011201': Decimal('7'),
    '011210': Decimal('7.1'),
    '011211': Decimal('5.2'),
    '011220': Decimal('5'),
    '011221': Decimal('3'),
    '012001': Decimal('8.6'),
    '012011': Decimal('7.5'),
    '012021': Decimal('5.2'),
    '012101': Decimal('7.1'),
    '012111': Decimal('5.2'),
    '012121': Decimal('2.9'),
    '012201': Decimal('6.3'),
    '012211': Decimal('2.9'),
    '012221': Decimal('1.7'),
    '100000': Decimal('9.8'),
    '100001': Decimal('9.5'),
    '100010': Decimal('9.4'),
    '100011': Decimal('8.7'),
    '100020': Decimal('9.1'),
    '100021': Decimal('8.1'),
    '100100': Decimal('9.4'),
    '100101': Decimal('8.9'),
    '100110': Decimal('8.6'),
    '100111': Decimal('7.4'),
    '100120': Decimal('7.7'),
    '100121': Decimal('6.4'),
    '100200': Decimal('8.7'),
    '100201': Decimal('7.5'),
    '100210': Decimal('7.4'),
    '100211': Decimal('6.3'),
    '100220': Decimal('6.3'),
    '100221': Decimal('4.9'),
    '101000': Decimal('9.4'),
    '101001': Decimal('8.9'),
    '101010': Decimal('8.8'),
    '101011': Decimal('7.7'),
    '101020': Decimal('7.6'),
    '101021': Decimal('6.7'),
    '101100': Decimal('8.6'),
    '101101': Decimal('7.6'),
    '101110': Decimal('7.4'),
    '101111': Decimal('5.8'),
    '101120': Decimal('5.9'),
    '101121': Decimal('5'),
    '101200': Decimal('7.2'),
    '101201': Decimal('5.7'),
    '101210': Decimal('5.7'),
    '101211': Decimal('5.2'),
    '101220': Decimal('5.2'),
    '101221': Decimal('2.5'),
    '102001': Decimal('8.3'),
    '102011': Decimal('7'),
    '102021': Decimal('5.4'),
    '102101': Decimal('6.5'),
    '102111': Decimal('5.8'),
    '102121': Decimal('2.6'),
    '102201': Decimal('5.3'),
    '102211': Decimal('2.1'),
    '102221': Decimal('1.3'),
    '110000': Decimal('9.5'),
    '110001': Decimal('9'),
    '110010': Decimal('8.8'),
    '110011': Decimal('7.6'),
    '110020': Decimal('7.6'),
    '110021': Decimal('7'),
    '110100': Decimal('9'),
    '110101': Decimal('7.7'),
    '110110': Decimal('7.5'),
    '110111': Decimal('6.2'),
    '110120': Decimal('6.1'),
    '110121': Decimal('5.3'),
    '110200': Decimal('7.7'),
    '110201': Decimal('6.6'),
    '110210': Decimal('6.8'),
    '110211': Decimal('5.9'),
    '110220': Decimal('5.2'),
    '110221': Decimal('3'),
    '111000': Decimal('8.9'),
    '111001': Decimal('7.8'),
    '111010': Decimal('7.6'),
    '111011': Decimal('6.7'),
    '111020': Decimal('6.2'),
    '111021': Decimal('5.8'),
    '111100': Decimal('7.4'),
    '111101': Decimal('5.9'),
    '111110': Decimal('5.7'),
    '111111': Decimal('5.7'),
    '111120': Decimal('4.7'),
    '111121': Decimal('2.3'),
    '111200': Decimal('6.1'),
    '111201': Decimal('5.2'),
    '111210': Decimal('5.7'),
    '111211': Decimal('2.9'),
    '111220': Decimal('2.4'),
    '111221': Decimal('1.6'),
    '112001': Decimal('7.1'),
    '112011': Decimal('5.9'),
    '112021': Decimal('3'),
    '112101': Decimal('5.8'),
    '112111': Decimal('2.6'),
    '112121': Decimal('1.5'),
    '112201': Decimal('2.3'),
    '112211': Decimal('1.3'),
    '112221': Decimal('0.6'),
    '200000': Decimal('9.3'),
    '200001': Decimal('8.7'),
    '200010': Decimal('8.6'),
    '200011': Decimal('7.2'),
    '200020': Decimal('7.5'),
    '200021': Decimal('5.8'),
    '200100': Decimal('8.6'),
    '200101': Decimal('7.4'),
    '200110': Decimal('7.4'),
    '200111': Decimal('6.1'),
    '200120': Decimal('5.6'),
    '200121': Decimal('3.4'),
    '200200': Decimal('7'),
    '200201': Decimal('5.4'),
    '200210': Decimal('5.2'),
    '200211': Decimal('4'),
    '200220': Decimal('4'),
    '200221': Decimal('2.2'),
    '201000': Decimal('8.5'),
    '201001': Decimal('7.5'),
    '201010': Decimal('7.4'),
    '201011': Decimal('5.5'),
    '201020': Decimal('6.2'),
    '201021': Decimal('5.1'),
    '201100': Decimal('7.2'),
    '201101': Decimal('5.7'),
    '201110': Decimal('5.5'),
    '201111': Decimal('4.1'),
    '201120': Decimal('4.6'),
    '201121': Decimal('1.9'),
    '201200': Decimal('5.3'),
    '201201': Decimal('3.6'),
    '201210': Decimal('3.4'),
    '201211': Decimal('1.9'),
    '201220': Decimal('1.9'),
    '201221': Decimal('0.8'),
    '202001': Decimal('6.4'),
    '202011': Decimal('5.1'),
    '202021': Decimal('2'),
    '202101': Decimal('4.7'),
    '202111': Decimal('2.1'),
    '202121': Decimal('1.1'),
    '202201': Decimal('2.4'),
    '202211': Decimal('0.9'),
    '202221': Decimal('0.4'),
    '210000': Decimal('8.8'),
    '210001': Decimal('7.5'),
    '210010': Decimal('7.3'),
    '210011': Decimal('5.3'),
    '210020': Decimal('6'),
    '210021': Decimal('5'),
    '210100': Decimal('7.3'),
    '210101': Decimal('5.5'),
    '210110': Decimal('5.9'),
    '210111': Decimal('4'),
    '210120': Decimal('4.1'),
    '210121': Decimal('2'),
    '210200': Decimal('5.4'),
    '210201': Decimal('4.3'),
    '210210': Decimal('4.5'),
    '210211': Decimal('2.2'),
    '210220': Decimal('2'),
    '210221': Decimal('1.1'),
    '211000': Decimal('7.5'),
    '211001': Decimal('5.5'),
    '211010': Decimal('5.8'),
    '211011': Decimal('4.5'),
    '211020': Decimal('4'),
    '211021': Decimal('2.1'),
    '211100': Decimal('6.1'),
    '211101': Decimal('5.1'),
    '211110': Decimal('4.8'),
    '211111': Decimal('1.8'),
    '211120': Decimal('2'),
    '211121': Decimal('0.9'),
    '211200': Decimal('4.6'),
    '211201': Decimal('1.8'),
    '211210': Decimal('1.7'),
    '211211': Decimal('0.7'),
    '211220': Decimal('0.8'),
    '211221': Decimal('0.2'),
    '212001': Decimal('5.3'),
    '212011': Decimal('2.4'),
    '212021': Decimal('1.4'),
    '212101': Decimal('2.4'),
    '212111': Decimal('1.2'),
    '212121': Decimal('0.5'),
    '212201': Decimal('1'),
    '212211': Decimal('0.3'),
    '212221': Decimal('0.1'),
}


LEVELS = {
    'AV': {
        'N': Decimal('0.0'),
        'A': Decimal('0.1'),
        'L': Decimal('0.2'),
        'P': Decimal('0.3'),
    },
    'PR': {
        'N': Decimal('0.0'),
        'L': Decimal('0.1'),
        'H': Decimal('0.2'),
    },
    'UI': {
        'N': Decimal('0.0'),
        'P': Decimal('0.1'),
        'A': Decimal('0.2'),
    },
    'AC': {
        'L': Decimal('0.0'),
        'H': Decimal('0.1'),
    },
    'AT': {
        'N': Decimal('0.0'),
        'P': Decimal('0.1'),
    },

    'VC': {
        'H': Decimal('0.0'),
        'L': Decimal('0.1'),
        'N': Decimal('0.2'),
    },
    'VI': {
        'H': Decimal('0.0'),
        'L': Decimal('0.1'),
        'N': Decimal('0.2'),
    },
    'VA': {
        'H': Decimal('0.0'),
        'L': Decimal('0.1'),
        'N': Decimal('0.2'),
    },

    'SC': {
        'H': Decimal('0.1'),
        'L': Decimal('0.2'),
        'N': Decimal('0.3'),
    },
    'SI': {
        'S': Decimal('0.0'),
        'H': Decimal('0.1'),
        'L': Decimal('0.2'),
        'N': Decimal('0.3'),
    },
    'SA': {
        'S': Decimal('0.0'),
        'H': Decimal('0.1'),
        'L': Decimal('0.2'),
        'N': Decimal('0.3'),
    },

    'CR': {
        'H': Decimal('0.0'),
        'M': Decimal('0.1'),
        'L': Decimal('0.2'),
    },
    'IR': {
        'H': Decimal('0.0'),
        'M': Decimal('0.1'),
        'L': Decimal('0.2'),
    },
    'AR': {
        'H': Decimal('0.0'),
        'M': Decimal('0.1'),
        'L': Decimal('0.2'),
    },

    'E': {
        'U': Decimal('0.2'),
        'P': Decimal('0.1'),
        'A': Decimal('0.0'),
    },
}
