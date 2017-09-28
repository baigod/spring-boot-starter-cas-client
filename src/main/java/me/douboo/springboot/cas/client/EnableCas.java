package me.douboo.springboot.cas.client;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.springframework.context.annotation.Import;

import me.douboo.springboot.cas.client.config.CasConfiguration;
import me.douboo.springboot.cas.client.config.ErrorPageConfiguration;

@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Import({ CasConfiguration.class, ErrorPageConfiguration.class })
@Documented
public @interface EnableCas {
}
