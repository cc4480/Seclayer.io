import { AuthType } from '../../../types.js';

export interface NewProfileForm {
  name: string;
  type: AuthType;
  headerName: string;
  headerValue: string;
  username: string;
  password: string;
  loginUrl: string;
  loginUsernameField: string;
  loginPasswordField: string;
  loginUsername: string;
  loginPassword: string;
}

export interface TestState {
  testUrl: string;
  loading: boolean;
  result: { success: boolean; status?: number; message: string } | null;
}

export const defaultForm: NewProfileForm = {
  name: '',
  type: 'bearer',
  headerName: '',
  headerValue: '',
  username: '',
  password: '',
  loginUrl: '',
  loginUsernameField: 'username',
  loginPasswordField: 'password',
  loginUsername: '',
  loginPassword: '',
};
