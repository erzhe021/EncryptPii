package com.ikea.crypto.client.util;

import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;

public final class DateUtils {

    private static final DateTimeFormatter FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    public static String toDate(long expiresAtEpochMillis) {
        Instant instant = Instant.ofEpochMilli(expiresAtEpochMillis);
        ZonedDateTime zdt = instant.atZone(ZoneId.systemDefault());
        return zdt.format(FORMATTER);
    }

    private DateUtils() {
    }

}
