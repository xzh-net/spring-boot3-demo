package net.xzh.iam.auth.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.fasterxml.jackson.datatype.jsr310.deser.LocalDateDeserializer;
import com.fasterxml.jackson.datatype.jsr310.deser.LocalDateTimeDeserializer;
import com.fasterxml.jackson.datatype.jsr310.ser.LocalDateSerializer;
import com.fasterxml.jackson.datatype.jsr310.ser.LocalDateTimeSerializer;
import org.springframework.boot.autoconfigure.jackson.Jackson2ObjectMapperBuilderCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

@Configuration
public class JacksonConfig {

    private static final String DATE_TIME_PATTERN = "yyyy-MM-dd HH:mm:ss";
    private static final String DATE_PATTERN = "yyyy-MM-dd";

    public static void configure(ObjectMapper om) {
        DateTimeFormatter dateTimeFmt = DateTimeFormatter.ofPattern(DATE_TIME_PATTERN);
        DateTimeFormatter dateFmt = DateTimeFormatter.ofPattern(DATE_PATTERN);
        om.registerModule(new JavaTimeModule());
        om.findAndRegisterModules();
        om.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
        om.registerModule(new SimpleModule()
                .addSerializer(LocalDateTime.class, new LocalDateTimeSerializer(dateTimeFmt))
                .addDeserializer(LocalDateTime.class, new LocalDateTimeDeserializer(dateTimeFmt))
                .addSerializer(LocalDate.class, new LocalDateSerializer(dateFmt))
                .addDeserializer(LocalDate.class, new LocalDateDeserializer(dateFmt)));
    }

    @Bean
    @Primary
    public ObjectMapper objectMapper() {
        ObjectMapper om = new ObjectMapper();
        configure(om);
        return om;
    }

    @Bean
    public Jackson2ObjectMapperBuilderCustomizer jacksonCustomizer() {
        return builder -> {
            builder.modules(new JavaTimeModule());
            builder.featuresToDisable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
        };
    }
}
