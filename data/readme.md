Base dataset is the cstnet-tls1.3

(.npy format)
https://drive.google.com/drive/folders/1JSsYmevkxQFanoKOi_i1ooA6pH3s9sDr (get the flow dataset) (put in this (./data) directory)

(.tsv format)
https://drive.google.com/drive/folders/11D2tkzPiJjTpQ9QzePQUIIpxtDxYpV2l?usp=drive_link

https://github.com/linwhitehat/ET-BERT/tree/main/datasets

![alt text](image.png)

First generate the data with virtual interfaces:
python data.py 

Then:
python databuilder.py --pcap-dir ./dataset_output/captures --out ./output.parquet
