export interface GetSecretOptions {
  userID: string;
  decrypt: boolean;
}

export interface ConstructorInitialiser {
  key?: string
  cache: boolean
}