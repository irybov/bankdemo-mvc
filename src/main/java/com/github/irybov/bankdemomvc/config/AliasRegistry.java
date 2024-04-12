package com.github.irybov.bankdemomvc.config;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.support.BeanDefinitionRegistryPostProcessor;
//import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.PriorityOrdered;

//@Configuration
public class AliasRegistry implements BeanDefinitionRegistryPostProcessor, PriorityOrdered {
	
	@Override
    public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) throws BeansException {
        beanFactory.registerAlias("accountServiceAlias", "accountServiceAlias");
        beanFactory.registerAlias("billServiceAlias", "billServiceAlias");
        beanFactory.registerAlias("operationServiceAlias", "operationServiceAlias");
    }

	@Override
	public void postProcessBeanDefinitionRegistry(BeanDefinitionRegistry beanRegistry) throws BeansException {
		beanRegistry.registerAlias("accountServiceAlias", "accountServiceAlias");
		beanRegistry.registerAlias("billServiceAlias", "billServiceAlias");
		beanRegistry.registerAlias("operationServiceAlias", "operationServiceAlias");
	}

	@Override
	public int getOrder() {
		return Ordered.HIGHEST_PRECEDENCE;
	}
	
}
