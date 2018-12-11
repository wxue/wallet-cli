package org.tron.common.filesystem;

import org.apache.commons.io.FileUtils;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;

public class SolcFileUtil {

    private static final String SOLC_RESOURCE_FILE = "/bin/" + getOS() + "/solc";
    private static final String SOLC_FILE = Config.SOLC_PATH + "/solc";

    private static String getOS() {
        String osName = System.getProperty("os.name").toLowerCase();
        if (osName.contains("win")) {
            return "win";
        } else if (osName.contains("linux")) {
            return "linux";
        } else if (osName.contains("mac")) {
            return "mac";
        } else {
            throw new RuntimeException("Can't find solc compiler: unrecognized OS: " + osName);
        }
    }

    public static File getSolcBinFile() {
        File file = new File(SOLC_FILE);
        if (file.exists()) {
            return file;
        }
        InputStream stream = SolcFileUtil.class.getResourceAsStream(SOLC_RESOURCE_FILE);
        File targetFile = new File(SOLC_FILE);
        try {
            FileUtils.copyInputStreamToFile(stream, targetFile);
        } catch (IOException e) {
            e.printStackTrace();
        }
        targetFile.setExecutable(true);
        return targetFile;
    }
}
