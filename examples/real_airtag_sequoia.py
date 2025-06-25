import logging
import os,re,sys
import plistlib
#import folium
from Crypto.Cipher import AES
from _login import get_account_sync
#from coordTransform import coordTransform
from findmy import FindMyAccessory
from findmy.reports import RemoteAnisetteProvider

KEYCHAIN_LABEL = "BeaconStore"
BASE_FOLDER = "com.apple.icloud.searchpartyd"
INPUT_PATH = os.path.join(os.getenv('HOME'), 'Library', BASE_FOLDER)
WHITELISTED_DIRS = {"OwnedBeacons", "BeaconNamingRecord"}
OUTPUT_PATH = os.path.join(os.getenv('HOME'), "plist_decrypt_output")
#start in your own docker
ANISETTE_SERVER = "http://localhost:6969"


def decrypt_plist(in_file_path: str, key: bytearray) -> dict:
    """
    Given an encrypted plist file at path in_file_path, decrypt it using key and AES-GCM and return the decrypted plist dict
    :param in_file_path: Source path of the encrypted plist file.
    Generally something like /Users/<username>/Library/com.apple.icloud.searchpartyd/OwnedBeacons/<UUID>.record
    :param key: Raw key to decrypt plist file with.
    Get it from the system shell command:
    security find-generic-password -l '<LABEL>' -w
    See: get_key(label: str)
    :returns: The decoded plist dict
    :rtype: dict
    :raises Exception: On failure to decrypt the encrypted plist
    """
    with open(in_file_path, 'rb') as f:
        encrypted_data = f.read()
    try:
        plist = plistlib.loads(encrypted_data)
    except Exception:
        raise ValueError("Invalid file format")
    if not isinstance(plist, list) or len(plist) < 3:
        raise ValueError("Invalid plist format")
    nonce, tag, ciphertext = plist[0], plist[1], plist[2]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    decrypted_plist = cipher.decrypt_and_verify(ciphertext, tag)
    try:
        decrypted_plist = plistlib.loads(decrypted_plist)
    except Exception:
        raise ValueError("Invalid decrypted data")
    if not isinstance(decrypted_plist, dict):
        raise ValueError(f"Expected plist to be a dictionary, but it was a {type(decrypted_plist)}")
    return decrypted_plist

def dump_plist(plist: dict, out_file_path: str) -> None:
    """
    Given a parsed plist dict, dump the decrypted plist file contents (this is xml) at out_file_path.
    This function will try to create missing folders.
    :param plist: Decrypted plist, created using any means.
    See also: decrypt_plist(in_file_path: str, key: bytearray) -> dict
    :param out_file_path: The output file name to create the decrypted & parsed plist xml file at.
    """
    os.makedirs(os.path.dirname(out_file_path), exist_ok=True)
    with open(out_file_path, 'wb') as out_f:
        plistlib.dump(plist, out_f)

def make_output_path(output_root: str, input_file_path: str, input_root_folder: str) -> str:
    """
    Transforms input_file_path into a dumping output_file_path along the lines of this idea (but it works generically for any level of nesting):
    Given:
    - input_file_path = /Users/<user>/Library/com.apple.icloud.searchpartyd/SomeFolder/.../<UUID>.record
    - output_root = /Users/<user>/my-target-folder
    - input_root_folder = /Users/<user>/Library/com.apple.icloud.searchpartyd
    """
    relative_path = os.path.relpath(input_file_path, input_root_folder)
    output_file_path = os.path.join(output_root, relative_path)
    return output_file_path

def decrypt_folder(input_root_folder: str, output_root: str, key: bytearray):
    for root, dirs, files in os.walk(input_root_folder):
        for dir_name in dirs:
            if dir_name in WHITELISTED_DIRS:
                dir_path = os.path.join(root, dir_name)
                for file_name in os.listdir(dir_path):
                    if file_name.endswith('.record'):
                        input_file_path = os.path.join(dir_path, file_name)
                        output_file_path = make_output_path(output_root, input_file_path, input_root_folder)
                        decrypted_plist = decrypt_plist(input_file_path, key)
                        dump_plist(decrypted_plist, output_file_path)

def extract_locations_from_file(content):
    locations = []
    matches = re.findall(r'lat\s*=\s*([-+]?\d+\.\d+),\s*lon\s*=\s*([-+]?\d+\.\d+)', content)
    for lat, lon in matches:
        lat = float(lat)
        lon = float(lon)
        #gcj_lon, gcj_lat = coordTransform.wgs84_to_gcj02(lon, lat)
        locations.append((lat, lon))
    return locations

def analyse_plist(plist_path: str) -> int:
    logging.basicConfig(level=logging.INFO)
    with open(plist_path, "rb") as f:
        airtag = FindMyAccessory.from_plist(f.read())
    print("Logging into account")
    anisette = RemoteAnisetteProvider(ANISETTE_SERVER)
    acc = get_account_sync(anisette)
    print("Fetching reports")
    reports = acc.fetch_last_reports(airtag)
    print("\nLocation reports:")
    text_reports = "\n".join(str(i) for i in sorted(reports))
    print(text_reports)
    locations = extract_locations_from_file(text_reports)
    #if not locations:
        #raise ValueError("未找到有效坐标")
    #try:
      #m = folium.Map(location=locations[0], zoom_start=10)
      #  folium.TileLayer(
      #      tiles='http://webst0{s}.is.autonavi.com/appmaptile?style=6&x={x}&y={y}&z={z}',
      #      max_zoom=18,
      #      subdomains=['1', '2', '3', '4'],
      #      attr='高德地图'
      #  ).add_to(m)
      #  for loc in locations:
      #      folium.Marker(loc).add_to(m)
      #  m.save("map.html")
    #except Exception as e:
        #print(f"绘制地图失败: {e}")
        # 输出locations到文件
    with open("locations.txt", "w", encoding="utf-8") as f:
    for loc in locations:
        f.write(f"{loc[0]},{loc[1]}\n")
    print("已将locations写入 locations.txt")
    return 0

def main(key: bytearray):
    decrypt_folder(INPUT_PATH, OUTPUT_PATH, key)
    result_list = []
    for root, dirs, files in os.walk(OUTPUT_PATH):
      for filename in files:
        file_path = os.path.join(root, filename)
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
            match = re.search(r'<key>model</key>\s*<string>(.*?)</string>', content, re.DOTALL)
            if match:
                model = match.group(1)
                result_list.append((model, file_path))
    if not result_list:
        print("No device models found.")
        return 1
    for idx, (model, path) in enumerate(result_list):
        print(f"{idx}: {model} ({path})")
    while True:
        try:
            choice = int(input("请选择你要提取的设备: "))
            if 0 <= choice < len(result_list):
                break
            print(f"请输入0到{len(result_list)-1}之间的数字")
        except Exception:
            print("输入不合法！")
    plist_path = result_list[choice][1]
    return analyse_plist(plist_path)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <your private key>", file=sys.stderr)
        print("The private key should be base64-encoded.", file=sys.stderr)
        sys.exit(1)
    sys.exit(main(bytearray.fromhex(sys.argv[1])))
