export const arrayBufferToHex = (buffer: ArrayBuffer) => {
  return Array.from(new Uint8Array(buffer))
    .map((x) => ("00" + x.toString(16)).slice(-2))
    .join("");
};

export const hexToArrayBuffer = (hex: string) => {
  if (!hex) {
    return new Uint8Array();
  }

  const arr = [];
  for (let i = 0, len = hex.length; i < len; i += 2) {
    arr.push(parseInt(hex.substring(i, 2), 16));
  }
  return new Uint8Array(arr);
};
