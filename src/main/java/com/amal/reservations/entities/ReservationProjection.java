package com.amal.reservations.entities;

import org.springframework.data.rest.core.config.Projection;

@Projection(name = "nomcl", types = { Reservation.class })
public interface ReservationProjection {
	public String getNomclient();
}
