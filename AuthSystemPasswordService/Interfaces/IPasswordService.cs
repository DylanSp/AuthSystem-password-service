namespace AuthSystemPasswordService.Interfaces
{
    public interface IPasswordService
    {
        HashedPassword GeneratePasswordHashAndSalt(PlaintextPassword password);
        bool CheckIfPasswordMatchesHash(PlaintextPassword password, HashedPassword hash);
    }
}
