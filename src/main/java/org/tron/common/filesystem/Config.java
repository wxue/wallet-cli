package org.tron.common.filesystem;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

//Package visible
//Do not change to public
class Config {
    private static final Logger logger = LoggerFactory.getLogger(Config.class);
    public static String LOCAL_SOURCE_PATH = "contracts/";

    public static String SOLIDITY_SOURCE_PATH = System.getProperty("user.home") + "/Compiler/source/";
    public static String TRACE_PATH = System.getProperty("user.home") + "/Compiler/trace/";
    public static String SOLC_PATH = System.getProperty("user.home") + "/Compiler/compiler/";
    public static String SAVED_PREFERENCE_PATH = System.getProperty("user.home") + "/Compiler/record/";

    static {
        {
            File dir = new File(Config.SOLIDITY_SOURCE_PATH);
            if (!dir.exists()) {
                dir.mkdirs();
            }
        }
        {
            File dir = new File(Config.TRACE_PATH);
            if (!dir.exists()) {
                dir.mkdirs();
            } else {
                List<File> list = new ArrayList<>();
                try {
                    Stream<Path> fileList = Files.list(Paths.get(Config.TRACE_PATH).toAbsolutePath());
                    fileList.forEach(item -> {
                        item.toFile().delete();
                    });
                } catch (IOException e) {
                    logger.error("Failed to delete file {}", e);
                }
            }
        }
        {
            File dir = new File(Config.SOLC_PATH);
            if (!dir.exists()) {
                dir.mkdirs();
            }
        }
        {
            File dir = new File(Config.SAVED_PREFERENCE_PATH);
            if (!dir.exists()) {
                dir.mkdirs();
            }
        }
    }
}
