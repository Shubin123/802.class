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


// columwise collection
51.la
amazonaws.com
biligame.com
crazyegg.com
elsevier.com
grammarly.com
ieee.org
microsoft.com
onlinedown.net
qqcom
spring
tiktok.com
walmart.com
youtube.com
51cto.com
ampproject.org
booking.com
criteo.com
facebook.com
gravatar.com
instagram.com
mozilla.org
opera.com
researchgate.net
springercom
toutiao.com
weibo.com
yy.com
163.com
apple.com
chia.net
ctrip.com
feishu.cn
guancha.cn
iqiyi.com
msn.com
oracle.com
runoob.com
squarespace.com
twimg.com
wikimedia.org
zhihu.com
acm.org
arxiv.org
chinatax.gov.cn
dailymotion.com
ggpht.com
huanqiu.com
jb51.net
naver.com
outbrain.com
sciencedirect.com
statcounter.com
twitter.com
wikipedia.org
adobe.com
asus.com
cisco.com
deepl.com
github.com
huawei.com
jd.com
netflix.com
overleaf.com
semanticscholar.org
steampowered.com
unity3d.com
wp.com
alibaba.com
atlassian.net
cloudflare.com
digitaloceanspaces.com
gitlab.com
hubspot.com
kugou.com
nike.com
paypal.com
sina.com.cn
t.co
vzex.com
xiaomi.com
alicdn.com
azureedge.net
cloudfront.net
duckduckgo.com
gmail.com
huya.com
leetcode-cn.com
notion, so
pinduoduo.com
smzdm.com
taboola.com
vivo.com.cn
ximalaya.com
alipay.com
baidu.com
cnblogs.com
eastday.com
goat.com
ibm.com
media-net
nvidia.com
python.org
snapchat.com
teads,tv
vk.com
yahoo.com
amap.com
billbili.com
codepen.io
eastmoney.com
google.com
icloud.com
mi.com
office.net
qcloud.com
sohu.com
thepaper.cn
vmware.com
yandex.ru


// row wise collection
'51.la' '51cto.com' '163.com' 'acm.org' 'asus.com' 'cloudflare.com'
 'duckduckgo.com' 'goat.com' 'icloud.com' 'amazonaws.com' 'ampproject.org'
 'apple.com' 'arxiv.org' 'cisco.com' 'digitaloceanspaces.com' 'gmail.com'
 'ibm.com' 'mi.com' 'biligame.com' 'booking.com' 'chia.net'
 'chinatax.gov.cn' 'deepl.com' 'gitlab.com' 'huya.com' 'media-net'
 'office.net' 'crazyegg.com' 'criteo.com' 'ctrip.com' 'dailymotion.com'
 'github.com' 'hubspot.com' 'leetcode-cn.com' 'nvidia.com' 'qcloud.com'
 'elsevier.com' 'facebook.com' 'feishu.cn' 'ggpht.com' 'huawei.com'
 'kugou.com' 'notion, so' 'python.org' 'sohu.com2' 'grammarly.com'
 'gravatar.com' 'guancha.cn' 'huanqiu.com' 'jd.com' 'nike.com'
 'pinduoduo.com' 'snapchat.com' 'thepaper.cn2' 'ieee.org' 'instagram.com'
 'iqiyi.com' 'jb51.net' 'netflix.com' 'paypal.com' 'smzdm.com' 'teads,tv'
 'vmware.com2' 'microsoft.com' 'mozilla.org' 'msn.com' 'naver.com'
 'overleaf.com' 'sina.com.cn' 'taboola.com' 'vk.com' 'yandex.ru2'
 'onlinedown.net' 'opera.com' 'oracle.com' 'outbrain.com'
 'semanticscholar.org' 't.co' 'vivo.com.cn' 'yahoo.com' 'None' 'qqcom'
 'researchgate.net' 'runoob.com' 'sciencedirect.com' 'steampowered.com'
 'vzex.com' 'ximalaya.com' 'amap.com' 'None' 'spring' 'springercom'
 'squarespace.com' 'statcounter.com' 'unity3d.com' 'xiaomi.com'
 'alipay.com' 'billbili.com' 'None' 'tiktok.com' 'toutiao.com' 'twimg.com'
 'twitter.com' 'wp.com' 'alicdn.com' 'baidu.com' 'codepen.io' 'None'
 'walmart.com' 'weibo.com' 'wikimedia.org' 'wikipedia.org' 'alibaba.com'
 'azureedge.net' 'cnblogs.com' 'eastmoney.com' 'None' 'youtube.com'
 'yy.com' 'zhihu.com' 'adobe.com' 'atlassian.net' 'cloudfront.net'
 'eastday.com' 'google.com' 'None'


