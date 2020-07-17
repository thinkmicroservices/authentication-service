 
package com.thinkmicroservices.ri.spring.auth.controller;

import javax.sql.DataSource;
import org.mockito.Mockito;
import static org.springframework.boot.jdbc.DatabaseDriver.H2;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;

/**
 *
 * @author cwoodward
 */
@TestConfiguration
public class TestConfig {
    
//    @Bean
//    @Primary
//    public DataSource dataSource() {
//        return new EmbeddedDatabaseBuilder()
//            .generateUniqueName(true)
//          
//                .setType(EmbeddedDatabaseType.H2)
//            .setScriptEncoding("UTF-8")
//            .ignoreFailedDrops(true)
//            //.addScript("schema.sql")
//            //.addScripts("user_data.sql", "country_data.sql")
//            .build();
//    }
}
