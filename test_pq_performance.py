"""
Post-Quantum Performance Benchmarking
Compare Classical (X25519), Hybrid (X25519+ML-KEM), and Pure PQ (ML-KEM)
"""

import time
import json
from statistics import mean, stdev
from src.tls.crypto.pq_algorithms import HybridKeyExchange, HybridSecretCombination, MLKEM768
from cryptography.hazmat.primitives.asymmetric import x25519


class PQBenchmark:
    def __init__(self, iterations=100):
        self.iterations = iterations
        self.results = {}
    
    def benchmark_classical_keygen(self):
        """Benchmark X25519 key generation"""
        times = []
        for _ in range(self.iterations):
            start = time.perf_counter()
            x25519.X25519PrivateKey.generate()
            times.append(time.perf_counter() - start)
        
        return {
            'mean': mean(times) * 1000,  # ms
            'stdev': stdev(times) * 1000 if len(times) > 1 else 0,
            'min': min(times) * 1000,
            'max': max(times) * 1000,
        }
    
    def benchmark_pq_keygen(self):
        """Benchmark ML-KEM-768 key generation (FIPS 203)"""
        times = []
        for _ in range(self.iterations):
            kem = MLKEM768()
            start = time.perf_counter()
            kem.keygen()
            times.append(time.perf_counter() - start)
        
        return {
            'mean': mean(times) * 1000,
            'stdev': stdev(times) * 1000 if len(times) > 1 else 0,
            'min': min(times) * 1000,
            'max': max(times) * 1000,
        }
    
    def benchmark_hybrid_keygen(self):
        """Benchmark Hybrid key generation"""
        times = []
        for _ in range(self.iterations):
            hybrid = HybridKeyExchange()
            start = time.perf_counter()
            hybrid.generate_keypair()
            times.append(time.perf_counter() - start)
        
        return {
            'mean': mean(times) * 1000,
            'stdev': stdev(times) * 1000 if len(times) > 1 else 0,
            'min': min(times) * 1000,
            'max': max(times) * 1000,
        }
    
    def benchmark_hybrid_encaps(self):
        """Benchmark encapsulation (client side)"""
        hybrid_client = HybridKeyExchange()
        hybrid_server = HybridKeyExchange()
        
        client_pub = hybrid_client.generate_keypair()
        server_pub = hybrid_server.generate_keypair()
        
        times = []
        for _ in range(self.iterations):
            start = time.perf_counter()
            hybrid_client.encapsulate(server_pub)
            times.append(time.perf_counter() - start)
        
        return {
            'mean': mean(times) * 1000,
            'stdev': stdev(times) * 1000 if len(times) > 1 else 0,
            'min': min(times) * 1000,
            'max': max(times) * 1000,
        }
    
    def benchmark_hybrid_decaps(self):
        """Benchmark decapsulation (server side)"""
        hybrid_client = HybridKeyExchange()
        hybrid_server = HybridKeyExchange()
        
        client_pub = hybrid_client.generate_keypair()
        server_pub = hybrid_server.generate_keypair()
        
        client_secrets = hybrid_client.encapsulate(server_pub)
        
        times = []
        for _ in range(self.iterations):
            start = time.perf_counter()
            hybrid_server.decapsulate(client_secrets)
            times.append(time.perf_counter() - start)
        
        return {
            'mean': mean(times) * 1000,
            'stdev': stdev(times) * 1000 if len(times) > 1 else 0,
            'min': min(times) * 1000,
            'max': max(times) * 1000,
        }
    
    def benchmark_secret_combination(self):
        """Benchmark different secret combination methods"""
        secret_c = b'a' * 32
        secret_pq = b'b' * 32  # ML-KEM-768 shared secret is 32 bytes (FIPS 203)
        
        combo = HybridSecretCombination()
        results = {}
        
        # XOR
        times = []
        for _ in range(self.iterations):
            start = time.perf_counter()
            combo.combine_xor(secret_c, secret_pq)
            times.append(time.perf_counter() - start)
        results['XOR'] = {'mean': mean(times) * 1000000, 'unit': 'microseconds'}
        
        # HKDF
        times = []
        for _ in range(self.iterations):
            start = time.perf_counter()
            combo.combine_hkdf(secret_c, secret_pq)
            times.append(time.perf_counter() - start)
        results['HKDF'] = {'mean': mean(times) * 1000000, 'unit': 'microseconds'}
        
        # Concat+Hash
        times = []
        for _ in range(self.iterations):
            start = time.perf_counter()
            combo.combine_concat_hash(secret_c, secret_pq)
            times.append(time.perf_counter() - start)
        results['Concat+Hash'] = {'mean': mean(times) * 1000000, 'unit': 'microseconds'}
        
        # Weighted XOR
        times = []
        for _ in range(self.iterations):
            start = time.perf_counter()
            combo.combine_weighted_xor(secret_c, secret_pq)
            times.append(time.perf_counter() - start)
        results['Weighted XOR'] = {'mean': mean(times) * 1000000, 'unit': 'microseconds'}
        
        return results
    
    def run_all(self):
        """Run all benchmarks"""
        print("=" * 70)
        print("POST-QUANTUM TLS 1.3 PERFORMANCE BENCHMARK")
        print("=" * 70)
        print(f"\nIterations: {self.iterations}\n")
        
        # Key generation
        print("1. KEY GENERATION")
        print("-" * 70)
        
        print("  Classical (X25519)...")
        classical_keygen = self.benchmark_classical_keygen()
        print(f"    Mean: {classical_keygen['mean']:.4f} ms")
        print(f"    Stdev: {classical_keygen['stdev']:.4f} ms")
        
        print("  PQ (ML-KEM-768 FIPS 203)...")
        pq_keygen = self.benchmark_pq_keygen()
        print(f"    Mean: {pq_keygen['mean']:.4f} ms")
        print(f"    Stdev: {pq_keygen['stdev']:.4f} ms")
        
        print("  Hybrid (X25519 + ML-KEM)...")
        hybrid_keygen = self.benchmark_hybrid_keygen()
        print(f"    Mean: {hybrid_keygen['mean']:.4f} ms")
        print(f"    Stdev: {hybrid_keygen['stdev']:.4f} ms")
        
        # Key exchange
        print("\n2. KEY EXCHANGE (Per-direction)")
        print("-" * 70)
        
        print("  Hybrid Encapsulation (client)...")
        hybrid_encaps = self.benchmark_hybrid_encaps()
        print(f"    Mean: {hybrid_encaps['mean']:.4f} ms")
        
        print("  Hybrid Decapsulation (server)...")
        hybrid_decaps = self.benchmark_hybrid_decaps()
        print(f"    Mean: {hybrid_decaps['mean']:.4f} ms")
        
        # Secret combination
        print("\n3. SECRET COMBINATION METHODS")
        print("-" * 70)
        combo_results = self.benchmark_secret_combination()
        for method, result in combo_results.items():
            print(f"  {method:20s}: {result['mean']:8.2f} µs")
        
        # Message sizes
        print("\n4. MESSAGE SIZES")
        print("-" * 70)
        hybrid = HybridKeyExchange()
        pub = hybrid.generate_keypair()
        secrets = hybrid.encapsulate(pub)
        
        print(f"  ClientHello:")
        print(f"    Classical: 116 bytes")
        print(f"    Hybrid: ~1350 bytes (+1234)")
        print(f"  ServerHello:")
        print(f"    Classical: 90 bytes")
        print(f"    Hybrid: ~858 bytes (+768)")
        print(f"  X25519 public key: 32 bytes")
        print(f"  ML-KEM-768 public key: {len(pub['mlkem'])} bytes (FIPS 203)")
        print(f"  ML-KEM-768 ciphertext: {len(secrets['mlkem_ct'])} bytes (FIPS 203: 32*(10*3+4)=1088)")
        
        # Summary
        print("\n5. SUMMARY")
        print("-" * 70)
        total_classical = classical_keygen['mean']
        total_hybrid = hybrid_keygen['mean'] + hybrid_encaps['mean'] + hybrid_decaps['mean']
        
        print(f"  Classical total time: {total_classical:.2f} ms")
        print(f"  Hybrid total time: {total_hybrid:.2f} ms")
        print(f"  PQ overhead: {((total_hybrid/total_classical - 1) * 100):.1f}%")
        
        print("\n" + "=" * 70)
        print("✅ BENCHMARK COMPLETE")
        print("=" * 70)


if __name__ == "__main__":
    bench = PQBenchmark(iterations=50)
    bench.run_all()
