import { createSlice, createAsyncThunk } from '@reduxjs/toolkit';

// Async thunk for fetching SEO data
export const fetchSEO = createAsyncThunk(
  'seo/fetchSEO',
  async (page, { rejectWithValue }) => {
    try {
      const response = await fetch(`/api/seo?page=${page}`);
      if (!response.ok) {
        throw new Error('Failed to fetch SEO data');
      }
      const data = await response.json();
      return data;
    } catch (error) {
      return rejectWithValue(error.message);
    }
  }
);

const seoSlice = createSlice({
  name: 'seo',
  initialState: {
    seoData: null,
    loading: false,
    error: null,
  },
  reducers: {
    clearSEO: (state) => {
      state.seoData = null;
      state.error = null;
    },
  },
  extraReducers: (builder) => {
    builder
      .addCase(fetchSEO.pending, (state) => {
        state.loading = true;
        state.error = null;
      })
      .addCase(fetchSEO.fulfilled, (state, action) => {
        state.loading = false;
        state.seoData = action.payload;
      })
      .addCase(fetchSEO.rejected, (state, action) => {
        state.loading = false;
        state.error = action.payload;
      });
  },
});

export const { clearSEO } = seoSlice.actions;
export default seoSlice.reducer;
