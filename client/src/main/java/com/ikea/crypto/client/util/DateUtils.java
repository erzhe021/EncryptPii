package com.ikea.crypto.client.util;

import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;

public class DateUtils {
    public static String toDate(long expiresAtEpochMillis) {
        Instant instant = Instant.ofEpochMilli(expiresAtEpochMillis);
        ZonedDateTime zdt = instant.atZone(ZoneId.of("Asia/Shanghai"));
        return zdt.format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
    }
}
