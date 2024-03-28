package com.gcu.data;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.gcu.data.entity.OrderEntity;
import com.gcu.data.repository.OrdersRepository;

@Service
public class OrdersDataService implements DataAccessInterface<OrderEntity> {
	@Autowired
	private OrdersRepository ordersRepository;
	
	/*
	 * Non-default constructor for injection
	 * */
	public OrdersDataService(OrdersRepository ordersRepository) {
		super();
		this.ordersRepository = ordersRepository;
	}

	/*
	 * CRUD: finder to return all entities
	 * */
	@Override
	public List<OrderEntity> findAll() {
		List<OrderEntity> orders = new ArrayList<OrderEntity>();
		
		try {
			// Get all the entity Orders
			Iterable<OrderEntity> ordersIterable = ordersRepository.findAll();
			
			// Convert to a List and return the List
			orders = new ArrayList<OrderEntity>();
			ordersIterable.forEach(orders::add);
			
		}
		catch (Exception e) {
			e.printStackTrace();
			
		}
		
		// Return the List
		return orders;
	}

	@Override
	public OrderEntity findById(int id) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public boolean create(OrderEntity order) {
		try {
			this.ordersRepository.save(order);
		}
		catch (Exception e) {
			e.printStackTrace();
			return false;
		}
		return true;
	}

	@Override
	public boolean update(OrderEntity order) {
		// TODO Auto-generated method stub
		return true;
	}

	@Override
	public boolean delete(OrderEntity order) {
		// TODO Auto-generated method stub
		return true;
	}


}
