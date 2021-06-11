package org.example;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class App {

    private static final String[] HOSTS = {
            "www.yahoo.co.jp",
            "www.shoprun.jp",
            "nowhere.example.com", // not exists
    };

    public static void main(String[] args) {
        java.security.Security.setProperty("networkaddress.cache.ttl" , "1");
        ExecutorService pool = Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors());
        for (int i = 0; i < 100000; i++) {
            pool.submit(() -> {
                Arrays.stream(HOSTS).forEach(host -> System.out.println(host + ": " + resolve(host)));
            });
        }
        pool.shutdown();
    }

    private static String resolve(String host) {
        try {
            InetAddress address = InetAddress.getByName(host);
            return address.getHostAddress();
        } catch (UnknownHostException e) {
            return "";
        }
    }
}
