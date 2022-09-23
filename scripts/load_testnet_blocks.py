import requests
import json
import argparse

parser = argparse.ArgumentParser(description='Script so useful.')
parser.add_argument("--root", type=int, default=0)
parser.add_argument("--head", type=int, default=1)
args = parser.parse_args()

root = args.root
head = args.head
blocks = []
for i in range(0, head):
    r = requests.get(f'https://testnet-insight.dashevo.org/insight-api-dash/block/{i}')
    block = r.json()
    print('{}'.format(i))
    blocks.append(block)

# print('{}'.format(blocks))
with open('scripts/testnet.json', 'w', encoding='utf-8') as f:
    json.dump(blocks, f, ensure_ascii=False, indent=4)
