namespace AuthSystemPasswordService.Interfaces
{
    public interface ICryptoRng
    {
        byte[] GetRandomBytes(int numBytes);
    }
}
