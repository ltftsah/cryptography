import java.math.BigInteger;
import java.security.*;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.Scanner;

public class Assignment2 {
    
    public static void main (String[] args) {

        try {
            //set up p and q as probable primes, these were generated and tested to be probable primes
            BigInteger p = new BigInteger("9542970870902820802659054404717059896702027851934909097249596771710688996298780449961935652606542982407304284749646784459568376849842489981268453134147663");

            BigInteger q = new BigInteger("11319229257134341627372509511752210895558666554133265376855409865693204797232027573798231926679599703106147138853391174662131817174884033800024295969088507");

            //ensure p and q are relatively prime
            assert isPrime(p, q) == true;

            //set up n , n =pq
            BigInteger n = p.multiply(q);

            //calculate euler tatient function; phi(n) = (p-1)(q-1) where p and q are both prime
            BigInteger one = new BigInteger("1");
            BigInteger phi = p.subtract(one).multiply(q.subtract(one));

            //set up encryption exponent e as 65537
            BigInteger e = new BigInteger("65537");

            //ensure e is relatively prime to phi(n) 
            assert isPrime(e, phi) == true;

            //compute value for decryption exponent d, the multiplicative inverse of e (mod phi(n)) using own extended Euclidean GCD algorithm
            BigInteger d = getExtendedGcd(e, phi)[1];

            //Check if file passed in, if not ask user for file
            File inputFile = null;
            if (args.length > 0){
                inputFile = new File(args[0]);
            }
            else {
                System.out.println("Please enter the name of the file you wish to encrypt: ");
                Scanner scan = new Scanner(System.in);
                inputFile = new File(scan.nextLine());
                scan.close();
            }
            
            // digitally sign digest of input binary using decryption method, 256 degest generated using shsa256, no randomness/redunacncy added to message
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            BigInteger m = new BigInteger(1, md.digest(Files.readAllBytes(inputFile.toPath())));

            BigInteger digest = decrypt(m, d, p, q);

            //save to files as hex
            Files.write(Paths.get("Signature.txt"), toHex(getBigIntBytes(digest)), StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.CREATE);
            Files.write(Paths.get("Modulus.txt"), toHex(getBigIntBytes(n)), StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.CREATE);
            

        } catch (Exception errorType) {
            System.out.println("The program ran into a wild: " + errorType);
        }
    }

    ///<Summary>
    /// Boolean check if two BigIntegers are relatively prime, calls getExtendedGcd
    ///</Summary>
    /// <param name="e">First BigInteger</param>
    /// <param name="phi">Second BigInteger</param>
    /// <returns> Returns true if paramaters are relatively prime, false if they're not </returns>
    private static boolean isPrime (BigInteger e, BigInteger phi){
        if (getExtendedGcd(e, phi)[0].equals(BigInteger.ONE)) return true;
        else return false;
    }

    ///<Summary>
    /// Implementation of extended Euclidean Algorithm as described in course notes, such that d = gcd(a,n) = xa + yn
    ///</Summary>
    /// <param name="a">First BigInteger</param>
    /// <param name="b">Second BigInteger</param>
    /// <returns> Array of BigIntegers, [0] is gcd(a,b), [1] is x, [2] is y </returns>
    private static BigInteger[] getExtendedGcd(BigInteger a, BigInteger b)
    { 
        if (a.equals(BigInteger.ZERO)) 
        { 
            BigInteger x = BigInteger.ZERO; 
            BigInteger y = BigInteger.ONE; 

            return new BigInteger[] {b, x, y}; 
        } 

        BigInteger[] gcd = getExtendedGcd(b.mod(a), a); 
        BigInteger tmp = gcd[1];
        gcd[1] = gcd[2].subtract((b.divide(a).multiply(gcd[1]))); 
        gcd[2] = tmp; 
  
        return gcd; 
    }

    ///<Summary>
    /// Method for decryption, calls crt(Chinese Remainder Theorem) method to increase efficiency
    ///</Summary>
    /// <param name="m">BigInteger representing message </param>
    /// <param name="d">BigInteger, decryption exponent </param>
    /// <param name="p">BigInteger, prime relative to q </param>
    /// <param name="q">BigInteger, prime relative to p </param>
    /// <returns> BigInteger representing "h(m)d (mod n) for message digest h(m)" as described in assignment spec </returns>
    private static BigInteger decrypt(BigInteger m, BigInteger d, BigInteger p, BigInteger q) {
        BigInteger dp = exponentiate(d, BigInteger.ONE, (q.subtract(BigInteger.ONE)));
        BigInteger dq = exponentiate(d, BigInteger.ONE, (q.subtract(BigInteger.ONE)));

        return crt(dp, dq, p, q, m);
    }

    ///<Summary>
    /// Chinese remainder theorem implementation, based on course notes.
    ///</Summary>
    /// <param name="dp"> BigInteger, d mod p </param>
    /// <param name="dq"> BigInteger, d mod q</param>
    /// <param name="p"> BigInteger, prime relative to p </param>
    /// <param name="q"> BigInteger, prime relative to q </param>
    /// <param name="m"> BigInteger, representing message </param>
    /// <returns> BigInteger representing "h(m)d (mod n) for message digest h(m)" as described in assignment spec </returns>
    private static BigInteger crt(BigInteger dp, BigInteger dq, BigInteger p, BigInteger q, BigInteger m){
        BigInteger mulInv = getExtendedGcd(q, p)[1]; //multiplicative inverse q mod p

        BigInteger m1 = exponentiate(m, dp, p);
        BigInteger m2 = exponentiate(m, dq, q);
        BigInteger h = mulInv.multiply(m1.subtract(m2)).mod(p);
        BigInteger finalM = m2.add(h.multiply(q));

        return finalM;
    }

    ///<Summary>
    /// Method to perform right to left modular exponentiation, based on pseudo code in module notes, as seen in hit assignments such as "Assignment 1"
    ///</Summary>
    /// <param name="x"> </param>
    /// <param name="exponent"> </param>
    /// <param name="modulus"> </param>
    /// <returns> </returns>
    private static BigInteger exponentiate(BigInteger x, BigInteger exponent, BigInteger modulus){
        BigInteger y = new BigInteger("1");
        
        String k = exponent.toString(2); //toString(radix) to convert bigInt to binary string
        
        for(int i = 1; i <= k.length(); i++){
			if(k.charAt(k.length()-i) == '1'){
				y = (y.multiply(x)).mod(modulus);
			}
			x = (x.multiply(x)).mod(modulus);
		}
		return y;
    }

    ///<Summary>
    /// Method to convert a byte array into its hexidecimal representation, as seen in hit assignments such as "Assignment 1"
    ///</Summary>
    /// <param name="bytes">Byte array to be converted to hexidecimal </param>
    /// <returns>Byte array representing hexidecimal </returns>
     private static byte[] toHex(byte[] bytes){
        StringBuilder temp = new StringBuilder();
        for (byte eachByte : bytes) temp.append(String.format("%02x", eachByte));
        return temp.toString().getBytes();
    }
    
    ///<Summary>
    /// Method to replace bigInteger.toByteArray() to deal with leading 0 issue, as seen in hit assignments such as "Assignment 1"
    ///</Summary>
    /// <param name="value">BigInteger to be converted to byte array </param>
    /// <returns>Byte array of "value" </returns>
    private static byte[] getBigIntBytes(BigInteger value){
        byte[] array = value.toByteArray();
        if (array[0] == 0) {
            byte[] temp = new byte[array.length - 1];
            System.arraycopy(array, 1, temp, 0, temp.length);
            array = temp;
        }
        return array;
    }
}
