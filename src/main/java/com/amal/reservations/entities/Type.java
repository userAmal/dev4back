package com.amal.reservations.entities;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonIgnore;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.OneToMany;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
@Data
@AllArgsConstructor
@NoArgsConstructor
@Entity

public class Type {
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long idty;
	private String typereservation;
	private String descriptionty;
	@JsonIgnore
	@OneToMany(mappedBy = "type")
	
	private List<Reservation> reservations;

	


	public Long getIdty() {
		return idty;
	}
	public void setIdty(Long idty) {
		this.idty = idty;
	}
	public String getTypereservation() {
		return typereservation;
	}
	public void setTypereservation(String typereservation) {
		this.typereservation = typereservation;
	}
	public String getDescriptionty() {
		return descriptionty;
	}
	public void setDescriptionty(String descriptionty) {
		this.descriptionty = descriptionty;
	}
	public List<Reservation> getReservations() {
		return reservations;
		}
		public void setProduits(List<Reservation> reservations) {
		this.reservations =reservations;
		}

	
}
