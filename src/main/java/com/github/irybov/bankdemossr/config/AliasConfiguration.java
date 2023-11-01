package com.github.irybov.bankdemossr.config;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanFactoryPostProcessor;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;

public class AliasConfiguration implements BeanFactoryPostProcessor {

	@Override
    public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) throws BeansException {
        beanFactory.registerAlias("accountService", "accountService");
        beanFactory.registerAlias("billService", "billService");
        beanFactory.registerAlias("operationService", "operationService");
    }
	
}
