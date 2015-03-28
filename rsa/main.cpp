#include <boost/multiprecision/cpp_int.hpp>
#include <boost/multiprecision/miller_rabin.hpp>
#include <iostream>

using int_type = boost::multiprecision::cpp_int;

template<size_t bits>
int_type random_prime()
{
   using namespace boost::random;
   using namespace boost::multiprecision;

   mt11213b base_gen(clock());
   independent_bits_engine<mt11213b, bits, int_type> gen(base_gen);
   //
   // We must use a different generator for the tests and number generation, otherwise
   // we get false positives.
   //
   mt19937 gen2(clock());

   for (;;) {
      int_type n = gen();
      if(miller_rabin_test(n, 25, gen2)) {
         return n;
      }
   }
}

int_type modular_inverse(const int_type& a, const int_type& n)
{
    int_type r = n, newr = a;
    int_type t = 0, newt = 1;
    while (newr) {
        int_type quotient = r / newr;
        int_type saved = newt;
        newt = t - quotient * saved;
        t = saved;
        saved = newr;
        newr = r - quotient * saved;
        r = saved;
    }
    assert(r <= 1);
    if (t < 0) t += n;
    assert((a*t)%n == 1);
    return t;
}

int main()
{
    // 1. Choose two distinct prime numbers p and q.
    const int_type p = 61;
    const int_type q = 53;
    std::cout << "p = " << p << std::endl;
    std::cout << "q = " << q << std::endl;
    // 2. Compute n = pq.
    const int_type n = p * q;
    std::cout << "n = " << n << std::endl;
    // 3. Compute phi(n) = phi(p)phi(q) =  (p − 1)(q − 1) = n - (p + q - 1)
    const int_type phi_n = n - (p + q - 1);
    std::cout << "phi(n) = " << phi_n << std::endl;
    // 4. Choose an integer e such that 1 < e < phi(n) and gcd(e, phi(n)) = 1; i.e., e and phi(n) are coprime.
    const int_type e = 17;
    assert(gcd(phi_n, e) == 1);
    // 5. Determine d as d == e^−1 (mod phi(n)); i.e., d is the multiplicative inverse of e (modulo phi(n)).
    assert(modular_inverse(42, 2017)==1969);
    const int_type d = modular_inverse(e, phi_n);
    std::cout << "d = " << d << std::endl;
    assert((e*d) % phi_n == 1);

    std::cout << "Public key: (" << n << ", " << e << ")\n";
    std::cout << "Private key: " << d << std::endl;

    const int_type m = 65;
    const int_type c = powm(m, e, n);
    std::cout << m << " encrypted: " << c << std::endl;
    std::cout << "and decrypted: " << powm(c, d, n) << std::endl;

    const int_type h = 123; // hash of message we wish to sign
    const int_type s = powm(h, d, n);
    std::cout << h << " signed: " << s << std::endl;
    std::cout << "orignal hash back: " << powm(s, e, n) << std::endl;
}
