// Copyright (c) 2023, Sudipto Chandra
// All rights reserved. Check LICENSE file for details.

import 'dart:typed_data';

@pragma('vm:prefer-inline')
Uint8List toBytes(List<int> items) =>
    (items is Uint8List) ? items : Uint8List.fromList(items);
