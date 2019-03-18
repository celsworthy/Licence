package celtech.roboxbase.licence;

import java.io.File;
import java.io.IOException;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Enumeration;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import libertysystems.stenographer.Stenographer;
import libertysystems.stenographer.StenographerFactory;

/**
 *
 * @author George Salter
 */
public class NoHardwareLicenceTimer 
{
    private static final Stenographer STENO = StenographerFactory.getStenographer(NoHardwareLicenceTimer.class.getName());
    
    private static NoHardwareLicenceTimer instance;
    
    private String timerFilePath = "timer.lic";
    
    public String getTimerFilePath()
    {
        return timerFilePath;
    }
    
    public void setTimerFilePath(String timerFilePath)
    {
        this.timerFilePath = timerFilePath;
    }

    /**
     * Class is singleton
     * Do not allow instantiation outside of class.
     */
    private NoHardwareLicenceTimer() {}
    
    public static NoHardwareLicenceTimer getInstance() 
    {
        if(instance == null)
        {
            instance = new NoHardwareLicenceTimer();
        }
        return instance;
    }
    
    public boolean resetNoHardwareLicenceTimer()
    {
        LocalDate newCutOffDate = LocalDate.now();
        List<byte[]> macAddresses = determineMacAddresses();
        
        try
        {
            // Encrypt new date with all current Mac addresses
            List<String> encryptedDates = macAddresses.stream()
                        .map(macAddress -> encryptCutOffDate(newCutOffDate, macAddress))
                        .map(bytes -> Base64.getEncoder().encodeToString(bytes))
                        .collect(Collectors.toList());
            
            File timerFile = new File(timerFilePath);
            if (timerFile.exists())
            {
                // We need to find any encrypted lines we don't have MAC addresses for
                List<String> fileContent = new ArrayList<>(Files.readAllLines(Paths.get(timerFilePath), StandardCharsets.UTF_8));
                List<byte[]> currentEncryptedDates = fileContent.stream()
                        .map(string -> Base64.getDecoder().decode(string))
                        .collect(Collectors.toList());
                
                List<String> unknownLines = new ArrayList<>();
                
                currentEncryptedDates.forEach((encryptedDate) -> {
                    boolean LineExistsForMac = macAddresses.stream()
                            .map(macAddress -> unencryptCutOffDate(encryptedDate, macAddress))
                            .findAny().isPresent();
                    
                    // Add lines to a list that we cannot unencrypt with any of our MAC addresses
                    if (!LineExistsForMac)
                    {
                        unknownLines.add(Base64.getEncoder().encodeToString(encryptedDate));
                    }
                });
                
                encryptedDates.addAll(unknownLines);
            }
                
            Files.write(Paths.get(timerFilePath), encryptedDates, StandardCharsets.UTF_8);
        } catch (IOException e)
        {
            STENO.exception("Error when renewing timer file", e);
            return false;
        }
        
        return true;
    }

    
    public boolean hasHardwareBeenCheckedInLast(int days) 
    {
        LocalDate cutOffDate = LocalDate.now().minusDays(days);
        
        try
        {
            File timerFile = new File(timerFilePath);
            if(timerFile.exists())
            {
                List<String> fileContent = new ArrayList<>(Files.readAllLines(Paths.get(timerFilePath), StandardCharsets.UTF_8));
                List<byte[]> encryptedDates = fileContent.stream()
                        .map(string -> Base64.getDecoder().decode(string))
                        .collect(Collectors.toList());
                List<byte[]> macAddresses = determineMacAddresses();
                
                for (byte[] macAddress : macAddresses)
                {
                    boolean dateValid = encryptedDates.stream()
                            .map(encryptedDate -> unencryptCutOffDate(encryptedDate, macAddress))
                            .filter(potentialDate -> isDateValid(potentialDate, cutOffDate))
                            .findFirst().isPresent();
                    if(dateValid)
                    {
                        return dateValid;
                    }
                }
            }
        } catch (IOException ex) 
        {
            STENO.exception("Exception during license timer check", ex);
        }
        
        return false;
    }
    
    private boolean isDateValid(Optional<String> potentialDate, LocalDate cutOffDate)
    {
        boolean dateValid = false;
        
        if(potentialDate.isPresent())
        {
            LocalDate dateToCheck = LocalDate.parse(potentialDate.get(), DateTimeFormatter.ISO_DATE);
            dateValid = cutOffDate.isBefore(dateToCheck);
        }
        
        return dateValid;
    }
    
    private byte[] encryptCutOffDate(LocalDate cutOffDate, byte[] macAddress) 
    {
        final byte[] encodedMessage = cutOffDate.format(DateTimeFormatter.ISO_DATE)
                .getBytes(Charset.forName("UTF-8"));
      
        try 
        {
            final Cipher cipher = Cipher.getInstance("AES/GCM/PKCS5Padding");
            final int blockSize = cipher.getBlockSize();
            
            // generate random IV using block size
            final byte[] ivData = new byte[blockSize];
            final SecureRandom rnd = SecureRandom.getInstance("SHA1PRNG");
            rnd.nextBytes(ivData);
            GCMParameterSpec parameterSpec = new GCMParameterSpec(128, ivData);

            cipher.init(Cipher.ENCRYPT_MODE, createSecretKeyFromMac(macAddress), parameterSpec);

            final byte[] encryptedMessage = cipher.doFinal(encodedMessage);

            // concatenate IV and encrypted message
            final byte[] ivAndEncryptedMessage = new byte[ivData.length
                    + encryptedMessage.length];
            System.arraycopy(ivData, 0, ivAndEncryptedMessage, 0, blockSize);
            System.arraycopy(encryptedMessage, 0, ivAndEncryptedMessage,
                    blockSize, encryptedMessage.length);

            return ivAndEncryptedMessage;
        } catch (GeneralSecurityException | IOException  e)
        {
            STENO.exception("Unexpected exception while encrypting timer file", e);
            return new byte[0];
        }
    }
    
    private Optional<String> unencryptCutOffDate(byte[] encryptedDate, byte[] macAddress) 
    {
        try 
        {
            final Cipher cipher = Cipher.getInstance("AES/GCM/PKCS5Padding");
            final int blockSize = cipher.getBlockSize();

            // retrieve random IV from start of the received message
            final byte[] ivData = new byte[blockSize];
            System.arraycopy(encryptedDate, 0, ivData, 0, blockSize);
            GCMParameterSpec parameterSpec = new GCMParameterSpec(128, ivData);

            // retrieve the encrypted message itself
            final byte[] encryptedMessage = new byte[encryptedDate.length - blockSize];
            System.arraycopy(encryptedDate, blockSize,
                    encryptedMessage, 0, encryptedMessage.length);

            cipher.init(Cipher.DECRYPT_MODE, createSecretKeyFromMac(macAddress), parameterSpec);

            final byte[] encodedMessage = cipher.doFinal(encryptedMessage);

            // concatenate IV and encrypted message
            final String message = new String(encodedMessage, Charset.forName("UTF-8"));

            return Optional.of(message);
        } catch (AEADBadTagException ex)
        {
            // This is an expected case when a Mac address is not the key for this line
            return Optional.empty();
        } catch (GeneralSecurityException | IOException ex) 
        {
            STENO.exception("Error occured during decryption of timer file", ex);
            return Optional.empty();
        }
    }
    
    private SecretKey createSecretKeyFromMac(byte[] macAddress) throws NoSuchAlgorithmException, IOException 
    {
        MessageDigest sha = MessageDigest.getInstance("SHA-1");
        byte[] macAddressKey = sha.digest(macAddress);
        macAddressKey = Arrays.copyOf(macAddressKey, 16);
        SecretKey secretKey = new SecretKeySpec(macAddressKey, "AES");
        return secretKey;
    }
    
    private List<byte[]> determineMacAddresses()
    {  
         List<byte[]> macAddresses = new ArrayList<>();
        
        try 
        {
            Enumeration<NetworkInterface> networkInterfaces = NetworkInterface.getNetworkInterfaces();
            while (networkInterfaces.hasMoreElements())
            {
                NetworkInterface networkInterface = networkInterfaces.nextElement();
                byte[] macAddress = networkInterface.getHardwareAddress();
                if (macAddress != null && macAddress.length != 0)
                {
                    macAddresses.add(macAddress);
                }
            }
        } catch (SocketException ex) 
        {
            STENO.exception("Error occured during decryption of timer file", ex);
        }
        
        return macAddresses;
    }
}
