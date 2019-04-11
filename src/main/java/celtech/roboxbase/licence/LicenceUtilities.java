package celtech.roboxbase.licence;

import com.google.common.io.ByteStreams;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import javax.crypto.Cipher;
import libertysystems.stenographer.Stenographer;
import libertysystems.stenographer.StenographerFactory;
import org.apache.commons.codec.binary.Base64;

/**
 * Singleton class providing methods for validating and caching licences and in turn
 * enabling and disabling features in Automaker
 * 
 * @author George Salter
 */
public class LicenceUtilities
{
    
    private static final Stenographer STENO = StenographerFactory.getStenographer(LicenceUtilities.class.getName());
    
    private static final String OWNER_KEY = "OWNER";
    private static final String END_DATE_KEY = "END_DATE";
    private static final String PRINTER_ID_KEY = "PRINTER_ID";
    private static final String LICENSE_TYPE_KEY = "LICENSE_TYPE";
    
    
    /**
     * Class is a "pure static class" with no instances.
     * Do not allow instantiation outside of class.
     */
    private LicenceUtilities() {}
    
    private static PublicKey getPublic()
    {
        try 
        {
            InputStream in = LicenceUtilities.class.getResourceAsStream("/celtech/resources/keys/publicKey");
            byte[] keyBytes = ByteStreams.toByteArray(in);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePublic(spec);
        } 
        catch (GeneralSecurityException | IOException ex) 
        {
            STENO.exception("An error occured when getting the public key", ex);
        }
        return null;
    }
    
    public static Optional<Licence> readEncryptedLicenceFile(File encryptedLicenceFile) 
    {
        STENO.trace("Begining read of encrypted licence file");
        
        String licenceText = null;
        
        try (BufferedReader bufferedReader = new BufferedReader(new FileReader(encryptedLicenceFile))) 
        {
            StringBuilder stringBuilder = new StringBuilder();
            String line = bufferedReader.readLine();
            PublicKey publicKey = getPublic();
            while(line != null) 
            {
                String decryptedLine = decryptLine(line, publicKey);
                if (decryptedLine != null)
                {
                    stringBuilder.append(decryptLine(line, publicKey));
                    stringBuilder.append("\n");
                }
                line = bufferedReader.readLine();
            }
            licenceText = stringBuilder.toString();
        }
        catch (IOException ex)
        {
            STENO.exception("Unexpected exception while trying to read licence file", ex);
        }
        
        if (licenceText != null) 
        {
            String[] licenceInfo = licenceText.split("\\r?\\n");

            String owner = "";
            String licenceEndDateString = "";
            List<String> printerIds = new ArrayList<>();
            LicenceType licenceType = LicenceType.AUTOMAKER_FREE;

            for (String licenceLine : licenceInfo) 
            {
                String[] lineInfo = licenceLine.split(":");
                String licenceInfoKey = lineInfo[0];
                String licenceInfoValue = lineInfo[1];

                switch(licenceInfoKey) 
                {
                    case OWNER_KEY:
                        owner = licenceInfoValue;
                        break;
                    case END_DATE_KEY:
                        licenceEndDateString = licenceInfoValue;
                        break;
                    case PRINTER_ID_KEY:
                        printerIds.add(licenceInfoValue);
                        break;
                    case LICENSE_TYPE_KEY:
                        if (licenceInfoValue.equals(LicenceType.AUTOMAKER_FREE.toString()))
                        {
                            licenceType = LicenceType.AUTOMAKER_FREE;
                        } 
                        else if (licenceInfoValue.equals(LicenceType.AUTOMAKER_PRO.toString())) 
                        {
                            licenceType = LicenceType.AUTOMAKER_PRO;
                        }
                        break;
                    default:
                        break;
                }
            }

            LocalDate licenceEndDate = parseDate(licenceEndDateString);
            if (licenceEndDate != null)
            {
                Licence licence = new Licence(licenceType, licenceEndDate, owner, printerIds);
                STENO.debug("Licence file read with type of: " + licence.getLicenceType());
                return Optional.of(licence);
            }
        }

        return Optional.empty();
    }
    
    private static String decryptLine(String encryptedLine, PublicKey key) 
    {
        try 
        {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, key);
            return new String(cipher.doFinal(Base64.decodeBase64(encryptedLine)), "UTF-8");
        } 
        catch (GeneralSecurityException 
                | UnsupportedEncodingException ex) {
            STENO.exception("Error when obtaining cipher instance.", ex);
        }
        return null;
    }
        
    /**
     * Turn a date String in the form of yyyy-MM-dd into a {@link LocalDate}
     *
     * @param date date in the form of a String
     * @return
     */
    private static LocalDate parseDate(String date) 
    {
        LocalDate parsedDate = null;
        try {
            DateTimeFormatter dtf = DateTimeFormatter.ISO_DATE;
            parsedDate = LocalDate.parse(date, dtf);
        }
        catch (DateTimeParseException ex)
        {
            STENO.exception("Error occured when parsing date.", ex);            
        }
        return parsedDate;
    }
    
    /**
     * Check if the licence is a free licence
     * 
     * @param licence
     * @return 
     */
    public static boolean isLicenceFreeVersion(Licence licence) 
    {
        return licence.getLicenceType() == LicenceType.AUTOMAKER_FREE;
    }
    
}
