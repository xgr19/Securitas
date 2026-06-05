# Defending against Traffic Analysis Attacks with Flexible In-Network Obfuscation (NSDI'26)

<!-- ![Workflow](./figs/workflow.png) -->

<div align="center">
<img src="./figs/workflow.png" width="50%" alt="Workflow">
</div>

<!-- Welcome to Securitas! Securitas protects encrypted traffic from traffic-analysis side channels through learning-guided packet fragmentation and fake-packet insertion. This release focuses on the Web/WF artifact path: DF attack-model training, Securitas policy training, generated P4 rule entries, and a Tofino-style P4 test program. -->

## Code Architecture

```text
-- web_attack_models
    -- preprocess_iscx.py         raw ISCX pcap -> data/iscx_session.pkl
    -- train_app_net.py           train APP-Net on ISCX sessions
    -- model.py                   APP-Net definition
    -- iscx_data.py               ISCX session loading utilities
    -- data/iscx_session.pkl      processed ISCX session data
    -- models/APP_net.pth         copied APP-Net checkpoint used by Securitas

-- web_securitas_training
    -- train_securitas.py         train the Securitas policy against APP-Net
    -- get_patch.py               export policy checkpoint(s) to P4 table entries
    -- generate_p4.py             compatibility wrapper for get_patch.py
    -- BSCAttack_agents.py        policy-gradient training agent
    -- model.py                   APP-Net definition
    -- iscx_data.py               ISCX session loading utilities
    -- utils.py                   evaluation helpers
    -- data/iscx_session.pkl      processed ISCX session data
    -- models/APP_net.pth         APP-Net checkpoint
    -- outputs/                   trained Securitas policies

-- p4
    -- Sec.p4
    -- ISCX_204.p4                generated table entries included by Sec.p4
    -- Sec_ports.json
    -- controller_session_id_conf.py
    -- sendpkt_testlogic.py
```

## Environment

```bash
conda env create -f environment.yml
conda activate securitas
```

## ISCX Data Processing

The ISCX VPN-nonVPN dataset can be downloaded from the CIC/UNB dataset page:

```text
https://www.unb.ca/cic/datasets/vpn.html
```

After extraction, organize the pcap files under:

```text
web_attack_models/raw_iscx/
  email/
  chat/
  streaming_multimedia/
  file_transfer/
  voip/
  p2p/
```

Then run:

```bash
cd web_attack_models
python preprocess_iscx.py --raw-data-dir raw_iscx --output data/iscx_session.pkl
cd ..
cp web_attack_models/data/iscx_session.pkl web_securitas_training/data/iscx_session.pkl
```

`preprocess_iscx.py` directly writes `iscx_session.pkl`; it does not create an
intermediate `iscx_flows.pkl`. By default it follows the original preprocessing
behavior: flow shuffling uses seed `1024`, while the train/test split uses
Python's global random stream.

## APP-Net Attack Model

The checked-in checkpoint is:

```text
web_attack_models/models/APP_net.pth
web_securitas_training/models/APP_net.pth
```

To retrain APP-Net:

```bash
cd web_attack_models
python train_app_net.py --data data/iscx_session.pkl --checkpoint models/APP_net.pth
cd ..
cp web_attack_models/models/APP_net.pth web_securitas_training/models/APP_net.pth
```

## Securitas Training

```bash
cd web_securitas_training
python train_securitas.py \
  --patch-length 204 \
  --split-ratio 0.7 \
  --loss-weights 0.6,0.2,0.2
cd ..
```

Default output:

```text
web_securitas_training/outputs/APP_net_204_split_88_0.7_0.6/best_mind.pth
web_securitas_training/outputs/APP_net_204_split_88_0.7_0.6/results.txt
```

The bandwidth term uses the real ISCX packet sizes from
`[timestamp, packet_size, direction]` records and is included in the policy loss.

## Generate P4 Rules

```bash
cd web_securitas_training
python generate_p4.py \
  --patch-length 204 \
  --policy-dir outputs/APP_net_204_split_88_0.7_0.6 \
  --split-ratio 0.7 \
  --max-patch-num 1 \
  --output-name ISCX_204.p4
cd ..
cp web_securitas_training/patch_p4_code/ISCX_204.p4 p4/ISCX_204.p4
```

Output:

```text
web_securitas_training/patch_p4_code/ISCX_204.p4
p4/ISCX_204.p4
```

The P4 export script is `get_patch.py`: it loads one or more `best_mind.pth`
policy checkpoints, samples patch actions, and writes the `const entries` block
included by `p4/Sec.p4`. `generate_p4.py` is kept as a short compatibility entry
point that calls the same code. The paper uses a mixed per-action choice rather
than a sequential first-TTL-then-fragment layout: for each non-zero policy
action, `--split-ratio` is the paper's `Pr`, i.e. the probability of exporting
`ac_should_fragment`; otherwise the action is exported as `ac_should_TTL`. The
default paper setting is `Pr = 0.7`, so small-TTL insertion has probability
`0.3`. `--fragment-ratio` is also accepted as a clearer alias for
`--split-ratio`.

## Citation

If you find Securitas useful in your research, please cite our paper:

```bibtex
@inproceedings{xie2026defending,
  title={Defending against Traffic Analysis Attacks with Flexible In-Network Obfuscation},
  author={Xie, Guorui and Li, Qing and Shi, Zhenning and Antichi, Gianni and Zhu, Yijia and Li, Kejun and Weng, Changxing and Miano, Sebastiano and Jiang, Yong and Xu, Mingwei},
  booktitle={Proceedings of the 23rd USENIX Symposium on Networked Systems Design and Implementation (NSDI 26)},
  pages={2043--2063},
  year={2026}
}
```
