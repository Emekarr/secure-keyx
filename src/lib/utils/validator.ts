export const verifyTextLength = (text: string, length: number) => {
  return !text ? false : text.length === length;
};
