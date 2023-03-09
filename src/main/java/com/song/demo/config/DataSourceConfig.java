package com.song.demo.config;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.context.annotation.Configuration;

@Configuration
@MapperScan(value = "com.song.demo.mapper" , sqlSessionFactoryRef = "SqlSessionFactory")
public class DataSourceConfig {
    public static void main(String[] args) {

    }
}
