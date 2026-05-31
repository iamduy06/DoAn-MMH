import os
import time
import csv
from charm.toolbox.pairinggroup import PairingGroup, GT
from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07
from charm.core.engine.util import objectToBytes

def run_benchmarks(num_iterations=5):
    print("="*50)
    print("  CP-ABE BSW07 BENCHMARK SUITE")
    print("="*50)

    try:
        group = PairingGroup('SS512')
        cpabe = CPabe_BSW07(group)
    except Exception as e:
        print(f"Lỗi khởi tạo Charm Crypto: {e}")
        return

    os.makedirs('results', exist_ok=True)
    csv_file = 'results/benchmark_results.csv'
    
    attr_counts = [5, 10, 20, 50]
    
    with open(csv_file, mode='w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow(['Num_Attributes', 'Setup_Time(ms)', 'KeyGen_Time(ms)', 'Encrypt_Time(ms)', 'Decrypt_Time(ms)', 'Ciphertext_Size(bytes)', 'SecretKey_Size(bytes)'])
        
        for n_attrs in attr_counts:
            print(f"\n[*] Đang test với {n_attrs} attributes...")
            
            # Setup
            t_setup = 0
            for _ in range(num_iterations):
                start = time.time()
                pk, mk = cpabe.setup()
                t_setup += (time.time() - start) * 1000
            avg_setup = t_setup / num_iterations
            
            # KeyGen
            attrs = [f"ATTR_{i}" for i in range(n_attrs)]
            t_keygen = 0
            sk_size = 0
            for _ in range(num_iterations):
                start = time.time()
                sk = cpabe.keygen(pk, mk, attrs)
                t_keygen += (time.time() - start) * 1000
            avg_keygen = t_keygen / num_iterations
            sk_size = len(objectToBytes(sk, group))
            
            # Encrypt
            policy = " and ".join(attrs[:min(5, n_attrs)]) # Encrypt với policy tối đa 5 thuộc tính để không quá phức tạp
            msg = group.random(GT)
            t_encrypt = 0
            ct_size = 0
            for _ in range(num_iterations):
                start = time.time()
                ct = cpabe.encrypt(pk, msg, policy)
                t_encrypt += (time.time() - start) * 1000
            avg_encrypt = t_encrypt / num_iterations
            ct_size = len(objectToBytes(ct, group))
            
            # Decrypt
            t_decrypt = 0
            for _ in range(num_iterations):
                start = time.time()
                rec_msg = cpabe.decrypt(pk, sk, ct)
                t_decrypt += (time.time() - start) * 1000
            avg_decrypt = t_decrypt / num_iterations
            
            if rec_msg == msg:
                print(f"  ✓ Giải mã thành công!")
            else:
                print(f"  ✗ Giải mã thất bại!")
                
            print(f"  - Setup: {avg_setup:.2f} ms")
            print(f"  - KeyGen: {avg_keygen:.2f} ms")
            print(f"  - Encrypt: {avg_encrypt:.2f} ms")
            print(f"  - Decrypt: {avg_decrypt:.2f} ms")
            print(f"  - Kích thước Ciphertext: {ct_size} bytes")
            
            writer.writerow([n_attrs, f"{avg_setup:.2f}", f"{avg_keygen:.2f}", f"{avg_encrypt:.2f}", f"{avg_decrypt:.2f}", ct_size, sk_size])
            
    print(f"\n[!] Hoàn thành. Kết quả đã lưu vào {csv_file}")

if __name__ == "__main__":
    run_benchmarks(num_iterations=5)
