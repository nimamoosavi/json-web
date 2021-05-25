package com.nicico.cost.jsonweb.service.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;

@Configuration
@PropertySource(value = "classpath:json-web-exception.properties", encoding = "UTF-8", ignoreResourceNotFound = true)
public class Config {
}
