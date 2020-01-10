package edu.osu.seclab.backwardslicing;

import java.util.List;

public interface ICollecter {
	public void clear();

	public void put(BackwardContext bc);

	public List<BackwardContext> retrieve();
}
