package celtech.roboxbase.licence;

import java.time.LocalDate;
import java.util.List;

/**
 * In code representation of the Licence, created by the {@link LicenceManager}
 * 
 * @author George Salter
 */
public class Licence {
    
    private final String owner;
    
    private final LicenceType licenseType;
    
    private final LocalDate endDate;
    
    private final List<String> printerIds;
    
    public Licence(LicenceType licenseType, LocalDate endDate, String owner, List<String> printerIds) {
        this.licenseType = licenseType;
        this.endDate = endDate;
        this.owner = owner;
        this.printerIds = printerIds;
    }
    
    public boolean checkLicenceInDate() {
        LocalDate localDate = LocalDate.now();
        return localDate.isBefore(endDate);
    }
    
    public boolean containsPrinterId(String printerId) {
        return printerIds.contains(printerId);
    }
    
    public String getFriendlyLicenceType() {
        if(licenseType == LicenceType.AUTOMAKER_PRO) {
            return "AutoMaker Pro";
        } else {
            return "AutoMaker Free";
        } 
    }
    
    public String getOwner() {
        return owner;
    }

    public LicenceType getLicenceType() {
        return licenseType;
    }

    public LocalDate getEndDate() {
        return endDate;
    }

    public List<String> getPrinterIds() {
        return printerIds;
    }
    
    public String toShortString() 
    {
        return getFriendlyLicenceType() + " - Expires: " + endDate;
    }
    
    private String buildPrinterIdsString() 
    {
        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append("Associated Printer IDs:");
        printerIds.forEach(id -> {
            stringBuilder.append("\n");
            stringBuilder.append(id);
        });
        return stringBuilder.toString();
    }
    
    @Override
    public String toString() 
    {
        return "Licence issued to: " + owner + "\n"
                + "Licence type: " + getFriendlyLicenceType() + "\n"
                + "Expires: " + endDate + "\n"
                + buildPrinterIdsString();
    }
}
