using Microsoft.EntityFrameworkCore;
using proyecto_final_webconfig.Data;
using proyecto_final_webconfig.Models.Entities;

namespace proyecto_final_webconfig.Repository
{
    public class EventsRepository : IEventsRepository
    {
        private readonly EspressoContext espressoContext;

        public EventsRepository(EspressoContext espressoContext)
        {
            this.espressoContext = espressoContext;
        }

        public async Task<IEnumerable<Event>> GetAllRecentsEvents()
        {
            return await espressoContext.Events.OrderByDescending(e => e.Timestamp).Include(e => e.TypeDetection).ToListAsync();
        }

        public async Task<Event> GetEventByID(int id)
        {
            return await espressoContext.Events.Where(x => x.Id == id).Include(e => e.TypeDetection).FirstAsync();
        }

        public async Task<IEnumerable<Event>> GetAllRecentsEventsByDevice(string MAC)
        {
           return await espressoContext.Events.Where(e => e.MacSource == MAC).OrderByDescending(e => e.Timestamp).Include(e => e.TypeDetection).ToListAsync();
        }

    }
}
