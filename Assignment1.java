import java.math.BigInteger;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.Cipher;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.nio.charset.*;
import java.util.Scanner;
import static java.lang.Math.toIntExact;


public class Assignment1{

    public static void main (String[] args){

        try{
            //Prime Modulus -p
            BigInteger p = new BigInteger("b59dd79568817b4b9f6789822d22594f376e6a9abc0241846de426e5dd8f6eddef00b465f38f509b2b18351064704fe75f012fa346c5e2c442d7c99eac79b2bc8a202c98327b96816cb8042698ed3734643c4c05164e739cb72fba24f6156b6f47a7300ef778c378ea301e1141a6b25d48f1924268c62ee8dd3134745cdf7323", 16);

            //Generator -g
            BigInteger g = new BigInteger("44ec9d52c8f9189e49cd7c70253c2eb3154dd4f08467a64a0267c9defe4119f2e373388cfa350a4e66e432d638ccdc58eb703e31d4c84e50398f9f91677e88641a2d2f6157e2f4ec538088dcf5940b053c622e53bab0b4e84b1465f5738f549664bd7430961d3e5a2e7bceb62418db747386a58ff267a9939833beefb7a6fd68", 16);

            //Public Shared Value -A
            BigInteger A = new BigInteger("5af3e806e0fa466dc75de60186760516792b70fdcd72a5b6238e6f6b76ece1f1b38ba4e210f61a2b84ef1b5dc4151e799485b2171fcf318f86d42616b8fd8111d59552e4b5f228ee838d535b4b987f1eaf3e5de3ea0c403a6c38002b49eade15171cb861b367732460e3a9842b532761c16218c4fea51be8ea0248385f6bac0d", 16);

            //Secret Value -b
            BigInteger b = new BigInteger(1023, new SecureRandom());

            //Public Shared Value -B
            BigInteger B = exponentiate(g, b, p);

            //Shared Secret -s
            BigInteger s = exponentiate(A, b, p);

            // generate k by SHA256-ing "s"
            SecretKeySpec k = hash(s);

            // generate IV for encryption
            IvParameterSpec IV = generateIV();

            // encrpt input file using AES in CBC mode using k as key and block size 128-bits
            // will need to generate 128-bit IV for this
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, k, IV);

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

            FileInputStream stream = new FileInputStream(inputFile);

            int fileLen = toIntExact(inputFile.length());
            int paddingLen = 16 - (fileLen % 16);
            int totalLen = fileLen + paddingLen;

            byte[] message = new byte[totalLen];
            stream.read(message);
            stream.close();

            add_padding(message, fileLen, paddingLen);

            byte[] result = cipher.doFinal(message);

            Files.write(Paths.get("Encryption.txt"), toHex(result), StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.CREATE);
            Files.write(Paths.get("IV.txt"), toHex(IV.getIV()), StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.CREATE);
            Files.write(Paths.get("DH.txt"), toHex(getBigIntBytes(B)), StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.CREATE);
        } 
        
        catch( IOException | GeneralSecurityException errorType){
            System.out.println(errorType);
        }
    }

    //method to perform right to left modular exponentiation, based on pseudo code in module notes
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

    //method to add padding to message
    private static void add_padding(byte[] bytes, int len, int padLen){
        bytes[len] = (byte) 128;
        for (int i = 1; i < padLen; i++) {
            bytes[len + 1] = (byte) 0;
        }
    }

    //method to hash using SHA256
    private static SecretKeySpec hash(BigInteger value) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] key = md.digest(getBigIntBytes(value));
        SecretKeySpec result = new SecretKeySpec(key, "AES");
        return result;
    }

    //method to replace bigInteger.toByteArray() to deal with leading 0 issue
    private static byte[] getBigIntBytes(BigInteger value){
        byte[] array = value.toByteArray();
        if (array[0] == 0) {
            byte[] temp = new byte[array.length - 1];
            System.arraycopy(array, 1, temp, 0, temp.length);
            array = temp;
        }
        return array;
    }

     //method to Generate Initial Vector for Encrptyion
     private static IvParameterSpec generateIV(){
        byte[] IV = new byte[16];
        SecureRandom rand = new SecureRandom();
        rand.nextBytes(IV);
        
        return new IvParameterSpec(IV);

     }

     //method to convert byte array to hexidecimal
     private static byte[] toHex(byte[] bytes){
        StringBuilder temp = new StringBuilder();
        for (byte eachByte : bytes) temp.append(String.format("%02x", eachByte));
        return temp.toString().getBytes();
    }

}