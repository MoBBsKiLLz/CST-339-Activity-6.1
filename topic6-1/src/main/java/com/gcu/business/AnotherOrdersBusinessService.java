package com.gcu.business;

import java.util.ArrayList;
import java.util.List;

import com.gcu.model.OrderModel;

public class AnotherOrdersBusinessService implements OrdersBusinessServiceInterface {

	@Override
	public void test() {
		// Simply print Hello to the console
		System.out.println("Hello from the AnotherOrdersBusinessService!");

	}
	
	@Override
	public List<OrderModel> getOrders(){
		// Create some Orders
		List<OrderModel> orders = new ArrayList<OrderModel>();
		orders.add(new OrderModel("5L", "0000000005", "Product 6", 6.00f, 6));
		orders.add(new OrderModel("6L", "0000000006", "Product 7", 7.00f, 7));
		orders.add(new OrderModel("7L", "0000000007", "Product 8", 8.00f, 8));
		orders.add(new OrderModel("8L", "0000000008", "Product 9", 9.00f, 9));
		orders.add(new OrderModel("9L", "0000000009", "Product 10", 10.00f, 10));
		
		return orders;
	}
	
	@Override
	public void init() {
		// Simply print a test message to the console
		System.out.println("Hello using the AnotherOrdersBusinessService init.");
	}
	
	@Override
	public void destroy() {
		// Simply print a test message to the console
		System.out.println("Hello using the AnotherOrdersBusinessService destroy.");
	}

}
