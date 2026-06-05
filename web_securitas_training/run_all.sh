#!/usr/bin/env bash
set -euo pipefail

python train_securitas.py \
  --patch-length 204 \
  --split-ratio 0.7 \
  --loss-weights 0.6,0.2,0.2 \
  "$@"

python generate_p4.py \
  --patch-length 204 \
  --policy-dir outputs/APP_net_204_split_88_0.7_0.6 \
  --split-ratio 0.7 \
  --max-patch-num 1 \
  --output-name ISCX_204.p4

cp patch_p4_code/ISCX_204.p4 ../p4/ISCX_204.p4
