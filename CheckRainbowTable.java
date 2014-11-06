import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;


public class CheckRainbowTable
{
    private final char[] charset;
    private final int passwordLength;
    private final int chainLength;
    private final int numChains;
    private final BigInteger modulo;
    private Map<String, String> table;


    public CheckRainbowTable(String charset, int passwordLength, int chainLength,
                        int numChains)
    {
        this.charset = charset.toCharArray();
        this.passwordLength = passwordLength;
        this.chainLength = chainLength;
        this.numChains = numChains;
        this.modulo = getPrimeModulus();
    }


    public static void main(String[] args)
    {
        String charset = "0123456789abcdefghijklmnopqrstuvwxyz";

        CheckRainbowTable table = new CheckRainbowTable(charset, 5, 5000, 125000);

        table.generate();

        String pass = table.lookup("86f7e437faa5a7fce15d1ddcb9eaeaea377667b8");
        System.out.println("lookup: " + pass);
    }


    public void generate()
    {

        table = new HashMap<String, String>(numChains);
        String start, end;
        int collisions = 0;

        long startTime = System.nanoTime();
        while (table.size() < numChains)
        {
            start = generateRandomPassword(passwordLength);
            end = generateChain(start);

            // Check for duplicate chains (collision merges)
            if (!table.containsKey(end))
            {
                table.put(end, start);
            }
            else
            {
                collisions++;
            }
        }

        long endTime = System.nanoTime();
        System.out.println("chains: " + numChains + " length: " + chainLength
                + " generated in " + seconds(startTime, endTime)
                + " (" + collisions + " collisions)");

        startTime = System.nanoTime();
        serialize("table.dat");
        endTime = System.nanoTime();
        System.out.println("serialized in " + seconds(startTime, endTime));
    }


    private String generateRandomPassword(int passwordLength)
    {
        StringBuilder builder = new StringBuilder(passwordLength);

        for (int i = 0; i < passwordLength; i++)
        {
            builder.append(charset[(int) (Math.random() * charset.length)]);
        }

        return builder.toString();
    }


    private String generateChain(String start)
    {
        String pass = start;
        String hash;

        for (int i = 0; i < chainLength; i++)
        {
            hash = SHA1.encodeData(pass.getBytes());
            pass = reduce(hash, i);
        }

        return pass;
    }


    private String reduce(String hash, int position)
    {
        BigInteger index;
        StringBuilder builder = new StringBuilder();

        BigInteger temp = new BigInteger(hash, 16);
        // Reduction needs to produce a different output for a different chain
        // position
        temp = temp.add(BigInteger.valueOf(position));
        temp = temp.mod(this.modulo);

        while (temp.intValue() > 0)
        {
            index = temp.mod(BigInteger.valueOf(charset.length));
            builder.append(charset[index.intValue()]);
            temp = temp.divide(BigInteger.valueOf(charset.length));
        }

        return builder.toString();
    }


    private BigInteger getPrimeModulus()
    {
        BigInteger max = BigInteger.ZERO;

        for (int i = 1; i <= passwordLength; i++)
        {
            max = max.add(BigInteger.valueOf(charset.length).pow(i));
        }

        BigInteger prime = max.nextProbablePrime();
        System.out.println("prime modulus: " + prime);
        return prime;
    }

    public String lookup(String hashToFind)
    {
        String hash, pass = null, lookup = null;
        long startTime = System.nanoTime();

        for (int i = chainLength - 1; i >= 0; i--)
        {
            hash = hashToFind;

            for (int j = i; j < chainLength; j++)
            {
                pass = reduce(hash, j);
                hash = SHA1.encodeData(pass.getBytes());
            }

            if (table.containsKey(pass))
            {
                lookup = lookupChain(table.get(pass), hashToFind);
                if (lookup != null)
                {
                    break;
                }
            }
        }

        long endTime = System.nanoTime();
        System.out.println("lookup took " + seconds(startTime, endTime));
        return lookup;
    }


    private String lookupChain(String start, String hashToFind)
    {
        String hash, pass = start, lookup = null;

        for (int j = 0; j < chainLength; j++)
        {
            hash = SHA1.encodeData(pass.getBytes());

            if (hash.equals(hashToFind))
            {
                lookup = pass;
                System.out.println("matched hash: " + hashToFind
                        + " (" + lookup + ")");
                break;
            }

            pass = reduce(hash, j);
        }

        return lookup;
    }


    private void serialize(String filename)
    {
        ObjectOutputStream out;
        try
        {
            out = new ObjectOutputStream(new FileOutputStream(filename));
            out.writeObject(table);
            out.close();
        }
        catch (IOException e)
        {
            e.printStackTrace();
        }
    }


    private String seconds(long startTime, long endTime)
    {
        return ((endTime - startTime) / 1000000000.0) + "s";
    }
	
}

class SHA1
{
	    private final static char[] hexArray = "0123456789abcdef".toCharArray();

	    public static byte[] encodeData(byte[] text, int offset, int length)
	    {
	        MessageDigest md;
	        byte[] sha1hash = {};

	        try
	        {
	            md = MessageDigest.getInstance("SHA-1");
	            md.update(text, offset, length);
	            sha1hash = md.digest();
	        }
	        catch (NoSuchAlgorithmException e)
	        {
	            e.printStackTrace();
	        }

	        return sha1hash;// return convertToHex(sha1hash);
	    }

	    public static String encodeData(byte[] text)
	    {
	        return convertToHex(encodeData(text, 0, text.length));
	    }

	    private static String convertToHex(byte[] data)
	    {
	        char[] hexChars = new char[data.length * 2];
	        for (int j = 0; j < data.length; j++)
	        {
	            int v = data[j] & 0xFF;
	            hexChars[j * 2] = hexArray[v >>> 4];
	            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
	        }
	        return new String(hexChars);
	    }

	    public static byte[] hexStringToByteArray(String s)
	    {
	        int len = s.length();
	        byte[] data = new byte[len / 2];
	        for (int i = 0; i < len; i += 2)
	        {
	            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
	                    + Character.digit(s.charAt(i + 1), 16));
	        }
	        return data;
	    }

	}



