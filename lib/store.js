import { configureStore } from '@reduxjs/toolkit';
import { persistStore, persistReducer } from 'redux-persist';
import storage from 'redux-persist/lib/storage';
import { combineReducers } from '@reduxjs/toolkit';
import profileReducer from './slices/profileSlice';
import authReducer from './slices/authSlice';
import seoReducer from './slices/seoSlice';

const persistConfig = {
  key: 'root',
  storage,
  whitelist: ['profile', 'seo'], // Only persist these reducers
  blacklist: ['auth'], // Don't persist auth for security
};

const rootReducer = combineReducers({
  profile: profileReducer,
  auth: authReducer,
  seo: seoReducer,
});

const persistedReducer = persistReducer(persistConfig, rootReducer);

export const store = configureStore({
  reducer: persistedReducer,
  middleware: (getDefaultMiddleware) =>
    getDefaultMiddleware({
      serializableCheck: {
        ignoredActions: ['persist/PERSIST', 'persist/REHYDRATE'],
      },
    }),
});

export const persistor = persistStore(store);
