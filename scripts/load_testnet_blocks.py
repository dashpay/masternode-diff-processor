import requests
import json
import argparse

def get_api_base(c):
    return 'insight.dashevo.org' if c == 'mainnet' else 'insight.testnet.networks.dash.org:3002'

parser = argparse.ArgumentParser(description='Script so useful.')
parser.add_argument("--root", type=int, default=0)
parser.add_argument("--head", type=int, default=1)
parser.add_argument("--chain", type=str, default='testnet')

args = parser.parse_args()

root = args.root
head = args.head
chain = args.chain
# blocks = []
base = get_api_base(chain)

blocks = []
for i in range(root, head):
    r = requests.get(f'https://{base}/insight-api-dash/block/{i}')
    block = r.json()
    # print('{}'.format(i))
    block_hash = block["hash"]
    block_height  = block["height"]
    merkle_root = block["merkleroot"]
    # print('store.put(new StoredBlock(new Block(params, {}, '
    #       'Sha256Hash.wrap(Sha256Hash.wrap("{}").getReversedBytes()), '
    #       'Sha256Hash.wrap("{}"), {}, {}, {}, new ArrayList<>()), new BigInteger(Hex.decode("{}")), {}));'
    #       .format(block["version"], block["previousblockhash"], merkle_root, block["time"], 0, block["nonce"], block["chainwork"], block_height))
    print('MerkleBlock::reversed({}, "{}", "{}"), '.format(block_height, block_hash, merkle_root))
    blocks.append(block)

# print('{}'.format(blocks))
with open('scripts/testnet.json', 'w', encoding='utf-8') as f:
    json.dump(blocks, f, ensure_ascii=False, indent=4)
